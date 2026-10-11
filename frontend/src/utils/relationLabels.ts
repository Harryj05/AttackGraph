export const RELATION_LABEL_MAP: Record<string, string> = {
  possible_access_control_issue: 'Possible access control issue',
  access_control_check: 'Possible access control issue',
  exposes_secret: 'Exposes secret',
  possible_reflected_input: 'Possible reflected input',
  reflected_input_check: 'Reflected input issue',
  has_endpoint: 'Has endpoint',
  exposes_endpoint: 'Exposes endpoint',
  contains_secret: 'Contains secret',
  accesses_data: 'Accesses data',
  grants_access: 'Grants access',
  leads_to: 'Leads to',
  contains: 'Contains',
  exposes: 'Exposes',
  accesses: 'Accesses',
  grants: 'Grants',
  leaks: 'Leaks',
};

export function formatRelationType(rel?: string | null): string {
  if (!rel) return '';
  const key = rel.toLowerCase().trim();
  if (RELATION_LABEL_MAP[key]) {
    return RELATION_LABEL_MAP[key];
  }
  // Fall back to raw name with underscores replaced by spaces
  return rel.replace(/_/g, ' ');
}
