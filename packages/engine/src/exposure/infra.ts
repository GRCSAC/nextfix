import { parseAllDocuments } from 'yaml';
import type { Exposure, InternetReach } from '../types.ts';
import { isComposeFile, isConfigFile, isManifestCandidate, readText, walkProject, type ProjectFile } from './files.ts';

/*
 * Internet reach from the infrastructure files in the repository: Terraform (AWS, Google
 * Cloud, Azure), CloudFormation, Kubernetes (Ingress, LoadBalancer services, gateways),
 * compose port bindings, platform files (fly.toml, vercel.json, netlify.toml, app.yaml,
 * render.yaml, serverless.yml, Procfile) and a reverse-proxy configuration. Every signal
 * carries the file it came from, so the verdict can be checked by hand.
 */

export interface InfraOptions {
  ignore?: string[];
  /** `internetFacing` from nextfix.config.json: a declaration that outranks the files. */
  declared?: boolean;
  log?: (msg: string) => void;
}

export interface InfraResult {
  reach: InternetReach;
  evidence: string[];
  /** Everything that pointed at the internet, and everything that pointed inward. */
  internet: string[];
  internal: string[];
}

const ANY_V4 = /["']?0\.0\.0\.0\/0["']?/;
const ANY_V6 = /["']?::\/0["']?/;

/** Top-level `resource "type" "name" { … }` blocks of an HCL file, bodies included (brace counting). */
export function hclResources(text: string): { type: string; name: string; body: string }[] {
  const out: { type: string; name: string; body: string }[] = [];
  const re = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    let depth = 1;
    let i = re.lastIndex;
    while (i < text.length && depth > 0) {
      const ch = text[i];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      else if (ch === '"') {
        i++;
        while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      } else if (ch === '#' || (ch === '/' && text[i + 1] === '/')) {
        while (i < text.length && text[i] !== '\n') i++;
      }
      i++;
    }
    out.push({ type: m[1]!, name: m[2]!, body: text.slice(re.lastIndex, i - 1) });
    re.lastIndex = i;
  }
  return out;
}

function attr(body: string, name: string): string | undefined {
  const m = new RegExp(`(?:^|\\n)\\s*${name}\\s*=\\s*([^\\n]+)`).exec(body);
  return m ? m[1]!.trim().replace(/^"(.*)"$/, '$1') : undefined;
}

/** `ingress { … }` style nested blocks of a resource body. */
function blocks(body: string, name: string): string[] {
  const out: string[] = [];
  const re = new RegExp(`(?:^|\\n)\\s*${name}\\s*\\{`, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    let depth = 1;
    let i = re.lastIndex;
    while (i < body.length && depth > 0) {
      if (body[i] === '{') depth++;
      else if (body[i] === '}') depth--;
      i++;
    }
    out.push(body.slice(re.lastIndex, i - 1));
    re.lastIndex = i;
  }
  return out;
}

function readTerraform(r: InfraResult, f: ProjectFile, text: string): void {
  for (const res of hclResources(text)) {
    const id = `${res.type} "${res.name}"`;
    switch (res.type) {
      case 'aws_security_group':
        for (const ing of blocks(res.body, 'ingress')) {
          if (ANY_V4.test(ing) || ANY_V6.test(ing)) r.internet.push(`${f.rel}: ${id} allows 0.0.0.0/0 on port ${attr(ing, 'from_port') ?? '?'}`);
        }
        break;
      case 'aws_security_group_rule':
        if (attr(res.body, 'type') === 'ingress' && (ANY_V4.test(res.body) || ANY_V6.test(res.body))) r.internet.push(`${f.rel}: ${id} allows 0.0.0.0/0 on port ${attr(res.body, 'from_port') ?? '?'}`);
        break;
      case 'aws_vpc_security_group_ingress_rule':
        if (ANY_V4.test(res.body) || ANY_V6.test(res.body)) r.internet.push(`${f.rel}: ${id} allows 0.0.0.0/0 on port ${attr(res.body, 'from_port') ?? '?'}`);
        break;
      case 'aws_lb':
      case 'aws_alb':
      case 'aws_elb': {
        const internal = attr(res.body, 'internal');
        if (internal === 'true') r.internal.push(`${f.rel}: ${id} is internal`);
        else r.internet.push(`${f.rel}: ${id} is internet-facing`);
        break;
      }
      case 'aws_apigatewayv2_api':
      case 'aws_cloudfront_distribution':
      case 'aws_amplify_app':
        r.internet.push(`${f.rel}: ${id}`);
        break;
      case 'aws_api_gateway_rest_api':
        if (/PRIVATE/.test(res.body)) r.internal.push(`${f.rel}: ${id} is a private endpoint`);
        else r.internet.push(`${f.rel}: ${id}`);
        break;
      case 'aws_lambda_function_url':
        if (attr(res.body, 'authorization_type') === 'NONE') r.internet.push(`${f.rel}: ${id} without authorization`);
        else r.internet.push(`${f.rel}: ${id}`);
        break;
      case 'google_compute_firewall':
        if ((attr(res.body, 'direction') ?? 'INGRESS').toUpperCase() === 'INGRESS' && ANY_V4.test(res.body)) r.internet.push(`${f.rel}: ${id} allows 0.0.0.0/0`);
        break;
      case 'google_cloud_run_service':
      case 'google_cloud_run_v2_service':
        if (/INGRESS_TRAFFIC_INTERNAL|ingress-status.*internal|run\.googleapis\.com\/ingress"?\s*[:=]\s*"?internal/i.test(res.body)) r.internal.push(`${f.rel}: ${id} ingress is internal`);
        else r.internet.push(`${f.rel}: ${id} accepts traffic from all sources`);
        break;
      case 'google_compute_global_forwarding_rule':
      case 'google_compute_forwarding_rule':
        if (/INTERNAL/.test(attr(res.body, 'load_balancing_scheme') ?? '')) r.internal.push(`${f.rel}: ${id} is internal`);
        else r.internet.push(`${f.rel}: ${id}`);
        break;
      case 'azurerm_network_security_rule': {
        const dir = (attr(res.body, 'direction') ?? '').toLowerCase();
        const access = (attr(res.body, 'access') ?? '').toLowerCase();
        const src = attr(res.body, 'source_address_prefix') ?? '';
        if (dir === 'inbound' && access === 'allow' && /^(\*|internet|0\.0\.0\.0\/0|any)$/i.test(src)) r.internet.push(`${f.rel}: ${id} allows inbound from ${src || 'any'} on port ${attr(res.body, 'destination_port_range') ?? '?'}`);
        break;
      }
      case 'azurerm_public_ip':
        r.internet.push(`${f.rel}: ${id} is a public IP`);
        break;
      case 'azurerm_linux_web_app':
      case 'azurerm_windows_web_app':
      case 'azurerm_app_service':
      case 'azurerm_container_app':
        if (attr(res.body, 'public_network_access_enabled') === 'false' || /external_enabled\s*=\s*false/.test(res.body)) r.internal.push(`${f.rel}: ${id} has public network access off`);
        else r.internet.push(`${f.rel}: ${id} is publicly reachable`);
        break;
      default:
        break;
    }
  }
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

const INTERNAL_LB_ANNOTATIONS = /aws-load-balancer-internal|aws-load-balancer-scheme"?\s*:\s*"?internal|load-balancer-type"?\s*:\s*"?[Ii]nternal|azure-load-balancer-internal"?\s*:\s*"?true|oci\.oraclecloud\.com\/load-balancer-type"?\s*:\s*"?internal/;

function readKubernetes(r: InfraResult, f: ProjectFile, docs: Record<string, unknown>[]): void {
  for (const d of docs) {
    const kind = String(d.kind);
    const name = String(asRecord(d.metadata)?.name ?? '');
    const spec = asRecord(d.spec);
    if (kind === 'Ingress') {
      const hosts = (Array.isArray(spec?.rules) ? spec!.rules : []).map((x) => asRecord(x)?.host).filter((h): h is string => typeof h === 'string');
      r.internet.push(`${f.rel}: Ingress ${name}${hosts.length ? ` for ${hosts.join(', ')}` : ''}`);
    } else if (kind === 'Service' && spec?.type === 'LoadBalancer') {
      const ann = JSON.stringify(asRecord(d.metadata)?.annotations ?? {});
      if (INTERNAL_LB_ANNOTATIONS.test(ann)) r.internal.push(`${f.rel}: Service ${name} is an internal load balancer`);
      else r.internet.push(`${f.rel}: Service ${name} is a LoadBalancer`);
    } else if (kind === 'Gateway' || kind === 'HTTPRoute' || kind === 'VirtualService') r.internet.push(`${f.rel}: ${kind} ${name}`);
  }
}

function readCloudFormation(r: InfraResult, f: ProjectFile, doc: Record<string, unknown>): void {
  const resources = asRecord(doc.Resources);
  if (!resources) return;
  for (const [name, res] of Object.entries(resources)) {
    const rr = asRecord(res);
    const type = String(rr?.Type ?? '');
    const props = asRecord(rr?.Properties) ?? {};
    if (type === 'AWS::ElasticLoadBalancingV2::LoadBalancer' || type === 'AWS::ElasticLoadBalancing::LoadBalancer') {
      if (String(props.Scheme ?? 'internet-facing') === 'internal') r.internal.push(`${f.rel}: ${name} (${type}) is internal`);
      else r.internet.push(`${f.rel}: ${name} (${type}) is internet-facing`);
    } else if (type === 'AWS::EC2::SecurityGroup') {
      for (const ing of Array.isArray(props.SecurityGroupIngress) ? props.SecurityGroupIngress : []) {
        const ir = asRecord(ing);
        if (ir && (ir.CidrIp === '0.0.0.0/0' || ir.CidrIpv6 === '::/0')) r.internet.push(`${f.rel}: ${name} allows 0.0.0.0/0 on port ${ir.FromPort ?? '?'}`);
      }
    } else if (type === 'AWS::EC2::SecurityGroupIngress' && (props.CidrIp === '0.0.0.0/0' || props.CidrIpv6 === '::/0')) r.internet.push(`${f.rel}: ${name} allows 0.0.0.0/0 on port ${props.FromPort ?? '?'}`);
    else if (type === 'AWS::ApiGateway::RestApi' || type === 'AWS::ApiGatewayV2::Api' || type === 'AWS::CloudFront::Distribution' || type === 'AWS::Serverless::Api' || type === 'AWS::Serverless::HttpApi') r.internet.push(`${f.rel}: ${name} (${type})`);
    else if (type === 'AWS::Serverless::Function' && /Type:\s*(Http)?Api/.test(JSON.stringify(props.Events ?? {}).replace(/"Type":"/g, 'Type: '))) r.internet.push(`${f.rel}: ${name} has an API event`);
  }
}

function readCompose(r: InfraResult, f: ProjectFile, doc: Record<string, unknown>): void {
  const services = asRecord(doc.services);
  if (!services) return;
  for (const [name, def] of Object.entries(services)) {
    const d = asRecord(def);
    for (const p of Array.isArray(d?.ports) ? d!.ports : []) {
      const s = typeof p === 'string' ? p : typeof p === 'number' ? String(p) : asRecord(p) ? `${asRecord(p)!.host_ip ?? ''}:${asRecord(p)!.published ?? ''}:${asRecord(p)!.target ?? ''}` : '';
      const m = /^(?:(\d+\.\d+\.\d+\.\d+|\[[^\]]+\]):)?(\d+)?(?::(\d+))?/.exec(s.replace(/^:/, ''));
      const bind = /^(127\.|\[::1\]|localhost)/.test(s) ? 'loopback' : /^(0\.0\.0\.0|\[::\])/.test(s) ? 'all' : s.includes('.') && /^\d/.test(s) ? 'address' : 'all';
      if (!m) continue;
      if (bind === 'loopback') r.internal.push(`${f.rel}: services.${name} publishes port ${m[2] ?? m[3] ?? '?'} on loopback only`);
    }
  }
}

function readPlatform(r: InfraResult, f: ProjectFile, text: string): void {
  const n = f.name.toLowerCase();
  if (n === 'fly.toml' && /\[\[services\]\]|\[http_service\]/.test(text)) r.internet.push(`${f.rel}: Fly.io service with public ports`);
  else if (n === 'vercel.json') r.internet.push(`${f.rel}: deployed on Vercel`);
  else if (n === 'netlify.toml') r.internet.push(`${f.rel}: deployed on Netlify`);
  else if (n === 'app.yaml' && /^\s*runtime:/m.test(text)) r.internet.push(`${f.rel}: App Engine service`);
  else if (n === 'render.yaml' && /type:\s*web/.test(text)) r.internet.push(`${f.rel}: Render web service`);
  else if (/^serverless\.ya?ml$/.test(n) && /^\s*-\s*(http|httpApi)\s*:/m.test(text)) r.internet.push(`${f.rel}: Serverless Framework HTTP events`);
  else if (n === 'procfile' && /^web:/m.test(text)) r.internet.push(`${f.rel}: web process for a hosting platform`);
  else if (n.endsWith('.conf') && /^\s*listen\s+(443|80)\b/m.test(text) && /^\s*server_name\s+(?!_\s*;)/m.test(text)) {
    const tls = /^\s*listen\s+443/m.test(text);
    r.internet.push(`${f.rel}: reverse proxy listens on ${tls ? '443 with TLS' : '80'}`);
  }
}

/** Read the infrastructure files and settle internet reach; a declaration in the config outranks them. */
export function analyzeInfra(rootDir: string, opts: InfraOptions = {}): InfraResult {
  const r: InfraResult = { reach: 'unknown', evidence: [], internet: [], internal: [] };
  for (const f of walkProject(rootDir, { ignore: opts.ignore })) {
    try {
      if (f.ext === 'tf') {
        const text = readText(f);
        if (text) readTerraform(r, f, text);
      } else if (isComposeFile(f) || isManifestCandidate(f) || (f.ext === 'json' && /(template|stack|cfn|cloudformation|sam)/i.test(f.rel))) {
        const text = readText(f);
        if (!text) continue;
        let docs: Record<string, unknown>[];
        try {
          docs = (f.ext === 'json' ? [JSON.parse(text)] : parseAllDocuments(text).map((d) => d.toJS())).map(asRecord).filter((d): d is Record<string, unknown> => !!d);
        } catch {
          continue;
        }
        if (isComposeFile(f)) for (const d of docs) readCompose(r, f, d);
        const k8s = docs.filter((d) => typeof d.kind === 'string' && typeof d.apiVersion === 'string');
        if (k8s.length) readKubernetes(r, f, k8s);
        for (const d of docs) if (d.Resources && (d.AWSTemplateFormatVersion || d.Transform || typeof asRecord(d.Resources) === 'object')) readCloudFormation(r, f, d);
      } else if (isConfigFile(f) || /^procfile$/i.test(f.name)) {
        const text = readText(f);
        if (text) readPlatform(r, f, text);
      }
    } catch (err) {
      opts.log?.(`Infra: ${f.rel}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  r.internet = [...new Set(r.internet)].slice(0, 12);
  r.internal = [...new Set(r.internal)].slice(0, 12);
  if (opts.declared === true) {
    r.reach = 'internet';
    r.evidence = ['nextfix.config.json: internetFacing is true', ...r.internet.slice(0, 3)];
  } else if (opts.declared === false) {
    r.reach = 'internal';
    r.evidence = ['nextfix.config.json: internetFacing is false', ...r.internal.slice(0, 3)];
  } else if (r.internet.length) {
    r.reach = 'internet';
    r.evidence = r.internet.slice(0, 4);
  } else if (r.internal.length) {
    r.reach = 'internal';
    r.evidence = r.internal.slice(0, 4);
  }
  return r;
}

/** Write the infrastructure verdict onto an exposure that may already carry an observation. */
export function applyInfra(exposure: Exposure, infra: InfraResult): void {
  if (infra.reach === 'unknown') return;
  exposure.reach = infra.reach;
  exposure.reachEvidence = [...infra.evidence];
}
