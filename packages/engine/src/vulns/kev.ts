import { Cache, DAY } from './cache.ts';
import { USER_AGENT } from '../version.ts';

export interface KevEntry {
  dateAdded: string;
  ransomware: boolean;
  product?: string;
}

const FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** CISA Known Exploited Vulnerabilities catalog, cached for a day. */
export async function fetchKev(cache: Cache, offline = false): Promise<Map<string, KevEntry>> {
  let entries = cache.get<Record<string, KevEntry>>('kev:catalog', offline);
  if (!entries) {
    if (offline) return new Map();
    const res = await fetch(FEED, { headers: { 'user-agent': USER_AGENT } });
    if (!res.ok) throw new Error(`KEV feed failed: ${res.status}`);
    const json = (await res.json()) as {
      vulnerabilities: { cveID: string; dateAdded: string; knownRansomwareCampaignUse?: string; product?: string }[];
    };
    entries = {};
    for (const v of json.vulnerabilities) {
      entries[v.cveID] = {
        dateAdded: v.dateAdded,
        ransomware: (v.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known',
        product: v.product,
      };
    }
    cache.set('kev:catalog', entries, DAY);
  }
  return new Map(Object.entries(entries));
}
