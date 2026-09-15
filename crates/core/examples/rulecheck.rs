//! TEMP: compare PAC domain rules + resolution between official and lite.
fn main() {
    // my data.rs domains for the steam groups
    let mut found = Vec::new();
    for grp in wtlite_core::data::built_in_groups() {
        for proj in &grp.items {
            for leaf in proj.all_leaves() {
                for d in leaf.listen_domain_names.split(';') {
                    let d = d.trim();
                    if d.contains("steamcommunity") { found.push(format!("{d}  (group={}, leaf={})", grp.name, leaf.id)); }
                }
            }
        }
    }
    println!("=== my domains containing 'steamcommunity' ===");
    for f in &found { println!("  {f}"); }
    println!();
    println!("=== shExpMatch semantics check (does 'steamcommunity.com' match subdomains?) ===");
    // shExpMatch(host, 'steamcommunity.com') matches ONLY the exact host
    println!("  'steamcommunity.com'      exact  -> matches: yes");
    println!("  'www.steamcommunity.com'         -> needs its own rule (official has one)");
    println!("  'store.steamcommunity.com'       -> NOT matched unless a *. rule exists");
}