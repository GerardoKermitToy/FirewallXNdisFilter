// Portable fixture archives use the same SDK constants without native WDK
// generation or a misleading native-wdk feature.
#[path = "../../../driver/build_constants.rs"]
mod build_constants;
fn main() {
    build_constants::generate();
}
