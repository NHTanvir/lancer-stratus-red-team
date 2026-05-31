pub mod aws;

use std::sync::Arc;
use anyhow::Result;
use tokio::sync::OnceCell;

pub struct CloudProviders {
    aws: OnceCell<Arc<aws::AwsProviders>>,
}

impl CloudProviders {
    pub fn new() -> Self {
        Self {
            aws: OnceCell::new(),
        }
    }

    pub async fn aws(&self) -> Result<Arc<aws::AwsProviders>> {
        let p = self
            .aws
            .get_or_try_init(|| async {
                let p = aws::AwsProviders::load().await?;
                Ok::<_, anyhow::Error>(Arc::new(p))
            })
            .await?;
        Ok(Arc::clone(p))
    }
}

impl Default for CloudProviders {
    fn default() -> Self {
        Self::new()
    }
}
