// Parses a claim written in the registration and request forms, such as
// address.locality or nationalities[*]. DCQL paths use strings for object
// members, null for every array element and numbers for array indices
// (OpenID4VP 1.0 §7.1).
window.eudiParseClaimPath = (text) => {
  const path = [];
  for (const segment of text.split('.')) {
    const name = segment.replace(/\[.*$/, '').trim();
    if (name) path.push(name);
    for (const bracket of segment.match(/\[[^\]]*\]/g) || []) {
      const inner = bracket.slice(1, -1).trim();
      if (inner === '*' || inner === '') path.push(null);
      else if (/^\d+$/.test(inner)) path.push(parseInt(inner, 10));
      else path.push(inner);
    }
  }
  return path;
};
