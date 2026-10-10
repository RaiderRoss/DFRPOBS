export type PageName = 'Overview' | 'Incidents' | 'Trigger events' | 'Work groups' | 'Evidence sources' | 'Evidence items'

export type TriggerEvent = {
  id: string
  externalEventId: string
  sourceSystem: string
  triggerType: string
  firedAt: string
  receivedAt: string
  payloadSha256: string
  // Correlation and the evidence bundle belong to the incident, not the alert.
  incidentId: string
}

export type CorrelationStatus = 'PENDING' | 'CORRELATED' | 'CLOSED' | 'FAILED'

/** Alerts a source grouped (for Slips: same attacker, same timewindow), with one bundle. */
export type Incident = {
  id: string
  sourceSystem: string
  incidentKey: string
  alertCount: number
  firstFiredAt: string
  lastFiredAt: string
  openedAt: string
  correlationStatus: CorrelationStatus
  correlatedAt: string | null
  windowStart: string
  windowEnd: string
}

export type LinkDisposition = 'PROPOSED' | 'CONFIRMED' | 'DISMISSED'

/** One entry in an alert's bundle: the item, how it got there, and any ruling on it. */
export type EvidenceLink = {
  id: string
  incidentId: string
  linkMethod: 'CAUSAL' | 'AUTO_TIME_WINDOW' | 'AUTO_RULE' | 'MANUAL'
  disposition: LinkDisposition
  rationale: string | null
  linkedBy: string | null
  linkedAt: string
  lateArrival: boolean
  // Null together until someone rules on the link.
  reviewedBy: string | null
  reviewedAt: string | null
  reviewNote: string | null
  evidenceSourceKey: string | null
  evidenceItem: EvidenceItem
}

export type WorkGroup = {
  id: string
  name: string
  classificationCode: string
  createdAt: string
}

export type EvidenceSource = {
  id: string
  sourceKey: string
  displayName: string
  workGroupId: string
  sourceType: string
  status: string
  expectedIntervalSeconds: number | null
  lastEvidenceAt: string | null
  registeredAt: string
}

export type EvidenceItem = {
  id: string
  workGroupId: string
  evidenceSourceId: string | null
  // Null together, and only for manually preserved items: the backend allows an artifact
  // with no coverage window rather than inventing one from createdAt. The listing has to
  // render those rows, so the nulls are in the type.
  eventStart: string | null
  eventEnd: string | null
  sourceArtifactId: string
  currentHash: string
  status: string
  createdAt: string
}

export type CustodyEvent = {
  id: string
  evidenceItemId: string
  sequence: number
  action: string
  performedBy: string | null
  occurredAt: string
  recordedAt: string
  artifactHashBefore: string | null
  artifactHashAfter: string
  prevEntryHash: string
  entryHash: string
  canonicalVersion: number
  detail: string
}

export type CustodyChainVerification = {
  evidenceItemId: string
  intact: boolean
  missingOrigin: boolean
  firstDivergentSequence: number | null
  length: number
  headEntryHash: string | null
}

export type IntegrityCheckResult = {
  evidenceItemId: string
  intact: boolean
  expectedHash: string
  observedHash: string
  status: string
  custodyEvent: CustodyEvent
}

/** Spring's PagedModel wire shape — `content` plus a page descriptor. */
export type Page<T> = {
  content: T[]
  page?: { size: number; number: number; totalElements: number; totalPages: number }
}

export type TriggerEventPage = Page<TriggerEvent>
export type EvidenceItemPage = Page<EvidenceItem>
export type EvidenceLinkPage = Page<EvidenceLink>
export type IncidentPage = Page<Incident>

export const navTabs: PageName[] = ['Overview', 'Incidents', 'Trigger events', 'Work groups', 'Evidence sources', 'Evidence items']

const baseUrl = import.meta.env.VITE_API_URL ?? 'http://localhost:8080'

let credentials = localStorage.getItem('dfraas.credentials') ?? ''

export function setCredentials(username: string, password: string) {
  credentials = btoa(`${username}:${password}`)
  localStorage.setItem('dfraas.credentials', credentials)
}

export function clearCredentials() {
  credentials = ''
  localStorage.removeItem('dfraas.credentials')
}

export function hasCredentials() {
  return Boolean(credentials)
}

async function send(path: string, options: RequestInit, accept: string): Promise<Response> {
  const headers = new Headers(options.headers)
  headers.set('Accept', accept)
  if (credentials) headers.set('Authorization', `Basic ${credentials}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')

  const response = await fetch(`${baseUrl}${path}`, { ...options, headers })
  if (!response.ok) {
    const problem = await response.json().catch(() => ({})) as { detail?: string; title?: string }
    throw new Error(problem.detail ?? problem.title ?? `${response.status} ${response.statusText}`)
  }
  return response
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await send(path, options, 'application/json')
  return response.status === 204 ? (undefined as T) : response.json() as Promise<T>
}

/** A released artifact: the bytes, the name the server gave them, and their digest as sent. */
export type EvidenceDownload = {
  blob: Blob
  fileName: string
  // Hex SHA-256 from the Repr-Digest header, or null if the header was missing or unreadable.
  sha256: string | null
}

/** `filename*=UTF-8''…` (RFC 6266) wins over plain `filename="…"` when both are present. */
function fileNameFrom(disposition: string | null, fallback: string) {
  if (!disposition) return fallback
  const extended = /filename\*=UTF-8''([^;]+)/i.exec(disposition)
  if (extended) return decodeURIComponent(extended[1])
  const plain = /filename="((?:\\.|[^"\\])*)"/i.exec(disposition)
  return plain ? plain[1].replace(/\\(.)/g, '$1') : fallback
}

/** RFC 9530 `sha-256=:<base64>:` to lower-case hex, the form the rest of the API uses. */
function sha256FromReprDigest(header: string | null) {
  const match = header && /sha-256=:([^:]+):/.exec(header)
  if (!match) return null
  return Array.from(atob(match[1]), (char) => char.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

/** Lower-case hex SHA-256 of a blob, computed in the browser. */
export async function sha256Hex(blob: Blob) {
  const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export const repositoryApi = {
  listTriggerEvents: (sourceSystem = '', page = 0, size = 50) => {
    const params = new URLSearchParams({ page: String(page), size: String(size), sort: 'receivedAt,desc' })
    if (sourceSystem) params.set('sourceSystem', sourceSystem)
    return request<TriggerEventPage>(`/api/trigger-events?${params}`)
  },
  getTriggerEvent: (id: string) => request<TriggerEvent>(`/api/trigger-events/${encodeURIComponent(id)}`),
  getTriggerEventByExternalId: (sourceSystem: string, externalEventId: string) =>
    request<TriggerEvent>(`/api/trigger-events/by-external-id?${new URLSearchParams({ sourceSystem, externalEventId })}`),
  listWorkGroups: (classificationCode = '') => request<WorkGroup[]>(
    `/api/work-groups${classificationCode ? `?${new URLSearchParams({ classificationCode })}` : ''}`,
  ),
  getWorkGroup: (id: string) => request<WorkGroup>(`/api/work-groups/${encodeURIComponent(id)}`),
  createWorkGroup: (name: string, classificationCode: string) => request<WorkGroup>('/api/work-groups', {
    method: 'POST',
    body: JSON.stringify({ name, classificationCode }),
  }),
  listEvidenceSources: (sourceKey = '') => request<EvidenceSource[]>(
    `/api/evidence-sources${sourceKey ? `?${new URLSearchParams({ sourceKey })}` : ''}`,
  ),
  getEvidenceSource: (id: string) => request<EvidenceSource>(`/api/evidence-sources/${encodeURIComponent(id)}`),
  createEvidenceSource: (source: Omit<EvidenceSource, 'id' | 'status' | 'lastEvidenceAt' | 'registeredAt'>) =>
    request<EvidenceSource>('/api/evidence-sources', {
      method: 'POST',
      body: JSON.stringify(source),
    }),
  // Paged, not a bare array: evidence_item grows at the rate the whole estate produces, so
  // the API has no unpaged listing to call. Sorted newest-first on createdAt — the timestamp
  // the repository stamps — rather than the source-asserted eventStart.
  listEvidenceItems: (workGroupId = '', includeDeleted = false, page = 0, size = 50) => {
    const params = new URLSearchParams({ page: String(page), size: String(size), sort: 'createdAt,desc' })
    if (workGroupId) params.set('workGroupId', workGroupId)
    if (includeDeleted) params.set('includeDeleted', 'true')
    return request<EvidenceItemPage>(`/api/evidence-items?${params}`)
  },
  // Newest opened first, by the repository's own clock.
  listIncidents: (sourceSystem = '', page = 0, size = 50) => {
    const params = new URLSearchParams({ page: String(page), size: String(size), sort: 'openedAt,desc' })
    if (sourceSystem) params.set('sourceSystem', sourceSystem)
    return request<IncidentPage>(`/api/incidents?${params}`)
  },
  getIncident: (id: string) => request<Incident>(`/api/incidents/${encodeURIComponent(id)}`),
  listIncidentAlerts: (id: string, page = 0, size = 50) =>
    request<TriggerEventPage>(`/api/incidents/${encodeURIComponent(id)}/trigger-events?${new URLSearchParams({ page: String(page), size: String(size) })}`),
  // Oldest link first, by when the repository made it, so late arrivals land at the end.
  listIncidentLinks: (incidentId: string, disposition: LinkDisposition | '' = '', page = 0, size = 50) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) })
    if (disposition) params.set('disposition', disposition)
    return request<EvidenceLinkPage>(`/api/incidents/${encodeURIComponent(incidentId)}/links?${params}`)
  },
  // The reviewer is whoever is signed in; the body carries only the reason. Each link can be
  // ruled on once — a second attempt is a 409 naming the ruling that stands.
  reviewEvidenceLink: (id: string, ruling: 'confirm' | 'dismiss', reason: string) =>
    request<EvidenceLink>(`/api/evidence-links/${encodeURIComponent(id)}/${ruling}`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  getEvidenceItem: (id: string) => request<EvidenceItem>(`/api/evidence-items/${encodeURIComponent(id)}`),
  getCustodyChain: (id: string) => request<CustodyEvent[]>(`/api/evidence-items/${encodeURIComponent(id)}/custody`),
  verifyCustodyChain: (id: string) => request<CustodyChainVerification>(`/api/evidence-items/${encodeURIComponent(id)}/custody/verification`),
  checkEvidenceIntegrity: (id: string) => request<IntegrityCheckResult>(`/api/evidence-items/${encodeURIComponent(id)}/integrity-checks`, { method: 'POST' }),
  // The only call that returns evidence bytes. The server re-hashes them before release and
  // appends an EXPORTED custody entry; a mismatch is refused with 422 and nothing is sent.
  // Accepts problem+json too, so a refusal arrives with its explanation.
  downloadEvidenceItem: async (id: string): Promise<EvidenceDownload> => {
    const response = await send(`/api/evidence-items/${encodeURIComponent(id)}/content`, {}, 'application/octet-stream, application/problem+json')
    return {
      blob: await response.blob(),
      fileName: fileNameFrom(response.headers.get('Content-Disposition'), `evidence-${id}`),
      sha256: sha256FromReprDigest(response.headers.get('Repr-Digest')),
    }
  },
  preserveEvidenceItem: (metadata: {
    sourceKey: string
    sourceArtifactId: string
    eventStart: string
    eventEnd: string
    sourceSha256: string
  }, file: File) => {
    const formData = new FormData()
    formData.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }))
    formData.append('file', file)
    return request<EvidenceItem>('/api/evidence-items', { method: 'POST', body: formData })
  },
}
