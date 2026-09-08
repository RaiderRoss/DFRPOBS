export type PageName = 'Overview' | 'Trigger events' | 'Work groups' | 'Evidence sources' | 'Evidence items'

export type TriggerEvent = {
  id: string
  externalEventId: string
  sourceSystem: string
  triggerType: string
  firedAt: string
  receivedAt: string
  payloadSha256: string
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
  eventStart: string | null
  eventEnd: string | null
  sourceArtifactId: string
  currentHash: string
  status: string
  createdAt: string
}

export type Page<T> = {
  content: T[]
  page?: { size: number; number: number; totalElements: number; totalPages: number }
}

export type TriggerEventPage = Page<TriggerEvent>
export type EvidenceItemPage = Page<EvidenceItem>

export const navTabs: PageName[] = ['Overview', 'Trigger events', 'Work groups', 'Evidence sources', 'Evidence items']

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

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  if (credentials) headers.set('Authorization', `Basic ${credentials}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')

  const response = await fetch(`${baseUrl}${path}`, { ...options, headers })
  if (!response.ok) {
    const problem = await response.json().catch(() => ({})) as { detail?: string; title?: string }
    throw new Error(problem.detail ?? problem.title ?? `${response.status} ${response.statusText}`)
  }
  return response.status === 204 ? (undefined as T) : response.json() as Promise<T>
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

  listEvidenceItems: (workGroupId = '', includeDeleted = false, page = 0, size = 50) => {
    const params = new URLSearchParams({ page: String(page), size: String(size), sort: 'createdAt,desc' })
    if (workGroupId) params.set('workGroupId', workGroupId)
    if (includeDeleted) params.set('includeDeleted', 'true')
    return request<EvidenceItemPage>(`/api/evidence-items?${params}`)
  },
  getEvidenceItem: (id: string) => request<EvidenceItem>(`/api/evidence-items/${encodeURIComponent(id)}`),
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
