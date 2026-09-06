export type PageName = 'Overview' | 'Trigger events' | 'Work groups'

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

export type TriggerEventPage = {
  content: TriggerEvent[]
  page?: { size: number; number: number; totalElements: number; totalPages: number }
}

export const navTabs: PageName[] = ['Overview', 'Trigger events', 'Work groups']

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
  if (options.body) headers.set('Content-Type', 'application/json')

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
}
