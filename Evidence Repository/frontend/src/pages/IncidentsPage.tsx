import { useEffect, useState } from 'react'
import { repositoryApi, type Incident, type TriggerEvent } from '../api/api'
import EvidenceBundlePanel from './EvidenceBundlePanel'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
}

/**
 * What an investigator works from: one row per incident rather than per alert. A source that
 * re-alerts about one attack (Slips does, every time the evidence crosses its threshold
 * again) shows up here once, with its alerts underneath and one evidence bundle to review.
 */
export default function IncidentsPage() {
    const [incidents, setIncidents] = useState<Incident[]>([])
    const [source, setSource] = useState('')
    const [selected, setSelected] = useState<Incident | null>(null)
    const [alerts, setAlerts] = useState<TriggerEvent[]>([])
    const [error, setError] = useState('')

    async function load() {
        try { setIncidents((await repositoryApi.listIncidents(source)).content); setError('') }
        catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load incidents.') }
    }

    async function inspect(id: string) {
        try {
            const [incident, page] = await Promise.all([repositoryApi.getIncident(id), repositoryApi.listIncidentAlerts(id)])
            setSelected(incident)
            setAlerts(page.content)
            setError('')
        } catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load the incident.') }
    }

    useEffect(() => { void load() }, [source])

    return <section className="workspace-grid">
        <article className="panel wide-panel">
            <div className="panel-header"><div><p className="panel-label">GET /api/incidents</p><h2>Incidents</h2></div><span className="chip secure">Read only</span></div>
            <p className="panel-copy">Alerts the source grouped — for Slips, the same attacker in the same timewindow — are one incident with one evidence bundle. Every alert is still kept on the Trigger events tab.</p>
            <div className="toolbar"><input aria-label="Filter by source system" placeholder="Filter source system" value={source} onChange={(event) => setSource(event.target.value)} /><button className="action" type="button" onClick={() => void load()}>Refresh</button></div>
            {error && <p className="error-message">{error}</p>}
            <div className="event-table-wrap"><table><thead><tr><th>Incident</th><th>Alerts</th><th>Fired</th><th>Status</th><th /></tr></thead><tbody>{incidents.map((row) => <tr key={row.id}>
                <td><strong>{row.incidentKey}</strong><small>{row.sourceSystem}</small></td>
                <td>{row.alertCount}</td>
                <td>{formatDate(row.firstFiredAt)}{row.lastFiredAt !== row.firstFiredAt && <small>to {formatDate(row.lastFiredAt)}</small>}</td>
                <td><span className={row.correlationStatus === 'PENDING' || row.correlationStatus === 'FAILED' ? 'status-pill warn' : 'status-pill'}>{row.correlationStatus}</span></td>
                <td><button className="text-button" type="button" onClick={() => void inspect(row.id)}>Inspect</button></td>
            </tr>)}</tbody></table>{incidents.length === 0 && <p className="empty-state">No incidents match this filter.</p>}</div>
        </article>
        <aside className="panel detail-panel"><p className="panel-label">GET /api/incidents/{'{id}'}</p><h2>Selected incident</h2>
            {!selected && <p className="panel-copy">Inspect an incident to see its alerts and review its evidence.</p>}
            {selected && <div className="detail-block"><span className="detail-kicker">{selected.correlationStatus}</span><strong>{selected.incidentKey}</strong><dl>
                <dt>Source</dt><dd>{selected.sourceSystem}</dd>
                <dt>Alerts</dt><dd>{selected.alertCount}</dd>
                <dt>Search window</dt><dd>{formatDate(selected.windowStart)} — {formatDate(selected.windowEnd)}</dd>
                <dt>Correlated</dt><dd>{selected.correlatedAt ? formatDate(selected.correlatedAt) : 'Not yet'}</dd>
            </dl>
                <span className="detail-kicker">Member alerts</span>
                <ul className="endpoint-list">{alerts.map((alert) => <li key={alert.id}><code>{alert.triggerType}</code>{formatDate(alert.firedAt)} <small>{alert.externalEventId}</small></li>)}</ul>
            </div>}
        </aside>
        {selected && <EvidenceBundlePanel incident={selected} onReviewed={() => void inspect(selected.id)} />}
    </section>
}
