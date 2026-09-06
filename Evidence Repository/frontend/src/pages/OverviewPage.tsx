import { useEffect, useState } from 'react'
import { clearCredentials, repositoryApi, type TriggerEvent, type WorkGroup } from '../api/api'

export default function OverviewPage() {
    const [events, setEvents] = useState<TriggerEvent[]>([])
    const [groups, setGroups] = useState<WorkGroup[]>([])

    useEffect(() => {
        void Promise.all([repositoryApi.listTriggerEvents(), repositoryApi.listWorkGroups()]).then(([eventPage, workGroups]) => {
            setEvents(eventPage.content)
            setGroups(workGroups)
        })
    }, [])

    return <section className="overview-grid">
        <article className="panel spotlight">
            <div className="panel-header"><div><p className="panel-label">Repository overview</p><h2>Evidence intake at a glance</h2></div><button className="text-button" type="button" onClick={() => { clearCredentials(); window.location.reload() }}>Disconnect</button></div>
            <p className="panel-copy">A live summary of the append-only records currently available to investigators.</p>
            <div className="metric-row"><div><span className="metric-value">{events.length}</span><span className="metric-label">recent trigger events</span></div><div><span className="metric-value">{new Set(events.map((event) => event.sourceSystem)).size}</span><span className="metric-label">source systems</span></div><div><span className="metric-value">{groups.length}</span><span className="metric-label">work groups</span></div></div>
        </article>
        <article className="panel"><p className="panel-label">API surface</p><h2>Available operations</h2><ul className="endpoint-list"><li><code>GET</code> trigger events, filtered and paginated</li><li><code>GET</code> evidence sources, optionally by source key</li><li><code>POST</code> evidence items as verified uploads</li><li><code>GET</code> preserved evidence metadata by id</li></ul></article>
    </section>
}
