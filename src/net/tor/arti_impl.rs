use crate::net::anonymous_net::AnonymousNet;
use crate::net::NetError;
use alloc::vec::Vec;
use alloc::string::String;

use crate::config::TorConfig;

#[cfg(feature = "arti")]
use std::sync::Arc;
#[cfg(feature = "arti")]
use tokio::runtime::Runtime;
#[cfg(feature = "arti")]
use tokio::sync::Mutex;
#[cfg(feature = "arti")]
use arti_client::{TorClient, TorClientConfig};
#[cfg(feature = "arti")]
use arti_client::DataStream;
#[cfg(feature = "arti")]
use futures::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
pub struct TorNet {
    #[cfg(feature = "arti")]
    runtime: Arc<Runtime>,
    #[cfg(feature = "arti")]
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    #[cfg(feature = "arti")]
    stream: Arc<Mutex<Option<DataStream>>>,
}

impl TorNet {
    pub fn new(config: &TorConfig) -> Result<Self, NetError> {
        #[cfg(feature = "arti")]
        {
            if !config.use_embedded {
                 // If embedded is disabled via config but we are in this method, 
                 // we might want to return error or fallback. 
                 // For now, we strictly follow the config.
                 return Err(NetError::NotImplemented);
            }

            let runtime = Runtime::new().map_err(|_| NetError::IOError)?;
            let builder = TorClientConfig::builder();
            
            // Apply proxy if configured
            if let Some(proxy_url) = &config.proxy {
                // Note: Real implementation would parse proxy_url and set it in builder.
                // builder.proxy(...);
                // For now we just acknowledge it.
                let _ = proxy_url;
            }

            let config = builder.build().map_err(|_| NetError::ConnectionFailed)?;
            
            // Create client inside the runtime
            let client = runtime.block_on(async {
                TorClient::create_bootstrapped(config).await
            }).map_err(|_| NetError::ConnectionFailed)?;

            Ok(Self {
                runtime: Arc::new(runtime),
                client: Arc::new(client),
                stream: Arc::new(Mutex::new(None)),
            })
        }
        #[cfg(not(feature = "arti"))]
        {
            let _ = config; // Suppress unused warning
            Err(NetError::NotImplemented)
        }
    }
}

impl AnonymousNet for TorNet {
    fn connect(&self, addr: &str) -> Result<(), NetError> {
        #[cfg(feature = "arti")]
        {
            let addr = String::from(addr);
            let client = self.client.clone();
            let stream_mutex = self.stream.clone();

            self.runtime.block_on(async move {
                // Arti expects address as "hostname:port"
                let stream = client.connect((addr.as_str(), 80)).await
                    .map_err(|_| NetError::ConnectionFailed)?;
                
                let mut guard = stream_mutex.lock().await;
                *guard = Some(stream);
                Ok(())
            })
        }
        #[cfg(not(feature = "arti"))]
        Err(NetError::NotImplemented)
    }

    fn listen(&self, _addr: &str) -> Result<(), NetError> {
        // Onion services require configuring onion service with arti
        Err(NetError::NotImplemented)
    }

    fn send(&self, data: &[u8]) -> Result<(), NetError> {
        #[cfg(feature = "arti")]
        {
            let stream_mutex = self.stream.clone();
            // We need to clone data because we are moving it into async block
            let data = data.to_vec(); 

            self.runtime.block_on(async move {
                let mut guard = stream_mutex.lock().await;
                if let Some(stream) = guard.as_mut() {
                    stream.write_all(&data).await.map_err(|_| NetError::IOError)?;
                    stream.flush().await.map_err(|_| NetError::IOError)?;
                    return Ok(());
                }
                Err(NetError::ConnectionFailed)
            })
        }
        #[cfg(not(feature = "arti"))]
        Err(NetError::NotImplemented)
    }

    fn receive(&self) -> Result<Vec<u8>, NetError> {
        #[cfg(feature = "arti")]
        {
            let stream_mutex = self.stream.clone();
            
            self.runtime.block_on(async move {
                let mut guard = stream_mutex.lock().await;
                if let Some(stream) = guard.as_mut() {
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).await.map_err(|_| NetError::IOError)?;
                    if n == 0 {
                        return Err(NetError::ConnectionFailed); // EOF
                    }
                    buf.truncate(n);
                    return Ok(buf);
                }
                Err(NetError::ConnectionFailed)
            })
        }
        #[cfg(not(feature = "arti"))]
        Err(NetError::NotImplemented)
    }

    fn address(&self) -> Result<String, NetError> {
        Err(NetError::NotImplemented)
    }
}
