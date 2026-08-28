//! Test-only facade for the protected-registry fixture.

#[cfg(test)]
#[path = "registry_fixture_persistence.rs"]
mod registry_fixture_persistence;

#[cfg(test)]
pub(crate) use registry_fixture_persistence::RegistryFixture;
