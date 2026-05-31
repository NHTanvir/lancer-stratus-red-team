use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Aws,
    Azure,
    Gcp,
    Kubernetes,
    Eks,
    EntraId,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::Aws => write!(f, "AWS"),
            Platform::Azure => write!(f, "Azure"),
            Platform::Gcp => write!(f, "GCP"),
            Platform::Kubernetes => write!(f, "Kubernetes"),
            Platform::Eks => write!(f, "EKS"),
            Platform::EntraId => write!(f, "EntraID"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" => Ok(Platform::Aws),
            "azure" => Ok(Platform::Azure),
            "gcp" | "google" => Ok(Platform::Gcp),
            "kubernetes" | "k8s" => Ok(Platform::Kubernetes),
            "eks" => Ok(Platform::Eks),
            "entraid" | "entra-id" | "entra_id" | "azuread" => Ok(Platform::EntraId),
            _ => anyhow::bail!("Unknown platform: {}", s),
        }
    }
}
