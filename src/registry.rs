use crate::technique::AttackTechnique;

pub fn all_techniques() -> Vec<&'static AttackTechnique> {
    inventory::iter::<AttackTechnique>.into_iter().collect()
}

pub fn find_technique(id: &str) -> Option<&'static AttackTechnique> {
    all_techniques().into_iter().find(|t| t.id == id)
}

pub fn techniques_for_platform(platform: &crate::platform::Platform) -> Vec<&'static AttackTechnique> {
    all_techniques()
        .into_iter()
        .filter(|t| &t.platform == platform)
        .collect()
}
