use axum::extract::Request;
use axum::middleware::{AddExtension, Next};
use axum::response::Response;
use axum::Extension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use futures_util::future::BoxFuture;
use rustls_pki_types::CertificateDer;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsStream;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Clone)]
pub struct Auth {
    pub username: String,
}

#[derive(Clone)]
pub struct TlsData<'a> {
    peer_certs: Option<Vec<CertificateDer<'a>>>,
}

#[derive(Clone)]
pub struct TlsAcceptor {
    inner: RustlsAcceptor,
}

impl TlsAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for TlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, TlsData<'static>>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let server_conn = stream.get_ref().1;
            let tls_data = TlsData {
                peer_certs: server_conn.peer_certificates().map(From::from),
            };
            let service = tower::ServiceBuilder::new()
                .layer(Extension(tls_data))
                .service(service);
            Ok((TlsStream::from(stream), service))
        })
    }
}

pub async fn auth_middleware(
    Extension(tls_data): Extension<TlsData<'_>>,
    mut request: Request,
    next: Next,
) -> Result<Response, &'static str> {
    if let Some(peer_certificates) = tls_data.peer_certs {
        // Take first client certificate
        let cert = X509Certificate::from_der(
            peer_certificates
                .first()
                .ok_or("missing client certificate")?,
        )
        .map_err(|_| "invalid client certificate")?
        .1;
        // Take first common name from certificate
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .ok_or("missing common name in client certificate")?
            .as_str()
            .map_err(|_| "invalid common name in client certificate")?;

        // Pass authentication to routes
        request.extensions_mut().insert(Auth {
            username: cn.to_string(),
        });
    } else {
        return Err("Missing client certificate");
    }

    Ok(next.run(request).await)
}
