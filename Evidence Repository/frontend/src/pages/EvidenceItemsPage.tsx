import { type FormEvent, useEffect, useState } from 'react'
import { repositoryApi, type CustodyChainVerification, type CustodyEvent, type EvidenceItem, type IntegrityCheckResult, type WorkGroup } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

/**
 * Manually preserved items have no coverage window at all — the repository stores null
 * rather than inventing one from createdAt, so the column has to say so instead of
 * rendering "Invalid Date".
 */
function formatWindow(start: string | null, end: string | null) {
    if (!start || !end) return 'Not asserted'
    return `${formatDate(start)} — ${formatDate(end)}`
}

const PAGE_SIZE = 25

export default function EvidenceItemsPage() {
    const [items, setItems] = useState<EvidenceItem[]>([])
    const [workGroups, setWorkGroups] = useState<WorkGroup[]>([])
    const [workGroupId, setWorkGroupId] = useState('')
    const [includeDeleted, setIncludeDeleted] = useState(false)
    const [page, setPage] = useState(0)
    const [totals, setTotals] = useState({ totalPages: 0, totalElements: 0 })
    const [error, setError] = useState('')

    const [lookupId, setLookupId] = useState('')
    const [item, setItem] = useState<EvidenceItem | null>(null)
    const [file, setFile] = useState<File | null>(null)
    const [form, setForm] = useState({ sourceKey: '', sourceArtifactId: '', eventStart: '', eventEnd: '', sourceSha256: '' })
    const [message, setMessage] = useState('')
    const [custody, setCustody] = useState<CustodyEvent[]>([])
    const [verification, setVerification] = useState<CustodyChainVerification | null>(null)
    const [integrity, setIntegrity] = useState<IntegrityCheckResult | null>(null)
    const [custodyMessage, setCustodyMessage] = useState('')

    async function load() {
        try {
            const result = await repositoryApi.listEvidenceItems(workGroupId, includeDeleted, page, PAGE_SIZE)
            setItems(result.content)
            setTotals({ totalPages: result.page?.totalPages ?? 0, totalElements: result.page?.totalElements ?? 0 })
            setError('')
        } catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load evidence items.') }
    }

    // The filter select needs names, not the UUIDs the API filters on.
    useEffect(() => { void repositoryApi.listWorkGroups().then(setWorkGroups).catch(() => setWorkGroups([])) }, [])

    useEffect(() => { void load() }, [workGroupId, includeDeleted, page])

    // Page 3 of a filter usually does not exist under the next one, so changing a filter
    // returns to the first page rather than leaving the table empty with no explanation.
    function applyFilter(next: () => void) { setPage(0); next() }

    async function lookup(event: FormEvent) {
        event.preventDefault()
        try { selectItem(await repositoryApi.getEvidenceItem(lookupId)); setMessage('') }
        catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Evidence item was not found.') }
    }

    function selectItem(nextItem: EvidenceItem) {
        setItem(nextItem)
        setCustody([])
        setVerification(null)
        setIntegrity(null)
        setCustodyMessage('')
        void loadCustody(nextItem.id)
    }

    async function loadCustody(id: string) {
        try { setCustody(await repositoryApi.getCustodyChain(id)) }
        catch (exception) { setCustodyMessage(exception instanceof Error ? exception.message : 'Unable to load the custody chain.') }
    }

    async function verifyCustody() {
        if (!item) return
        try { setVerification(await repositoryApi.verifyCustodyChain(item.id)); setCustodyMessage('Custody chain verified.') }
        catch (exception) { setCustodyMessage(exception instanceof Error ? exception.message : 'Unable to verify the custody chain.') }
    }

    async function checkIntegrity() {
        if (!item || !window.confirm('Run an integrity check? This appends a custody event.')) return
        try {
            setIntegrity(await repositoryApi.checkEvidenceIntegrity(item.id))
            setCustodyMessage('Integrity check recorded in the custody chain.')
            await loadCustody(item.id)
        } catch (exception) { setCustodyMessage(exception instanceof Error ? exception.message : 'Unable to check evidence integrity.') }
    }

    async function preserve(event: FormEvent) {
        event.preventDefault()
        if (!file) { setMessage('Choose an artifact file before preserving it.'); return }
        try {
            const preserved = await repositoryApi.preserveEvidenceItem({ ...form, eventStart: new Date(form.eventStart).toISOString(), eventEnd: new Date(form.eventEnd).toISOString() }, file)
            selectItem(preserved)
            setMessage('Evidence item preserved and verified.')
            void load()
        } catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Evidence item could not be preserved.') }
    }

    return <section className="workspace-grid item-grid">
        <article className="panel wide-panel">
            <div className="panel-header"><div><p className="panel-label">GET /api/evidence-items</p><h2>Preserved artifacts</h2></div><span className="chip secure">Digest only</span></div>
            <div className="toolbar">
                <select aria-label="Filter by classification" value={workGroupId} onChange={(event) => applyFilter(() => setWorkGroupId(event.target.value))}>
                    <option value="">All classifications</option>
                    {workGroups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
                </select>
                <label className="toggle-field"><input type="checkbox" checked={includeDeleted} onChange={(event) => applyFilter(() => setIncludeDeleted(event.target.checked))} />Include deleted</label>
                <button className="action" type="button" onClick={() => void load()}>Refresh</button>
            </div>
            {error && <p className="error-message">{error}</p>}
            <div className="event-table-wrap"><table><thead><tr><th>Artifact</th><th>Coverage</th><th>Preserved</th><th>Digest</th><th>Status</th><th /></tr></thead><tbody>{items.map((row) => <tr key={row.id}><td><strong>{row.sourceArtifactId ?? 'Manual preservation'}</strong><small>{row.id}</small></td><td>{formatWindow(row.eventStart, row.eventEnd)}</td><td>{formatDate(row.createdAt)}</td><td><code>{row.currentHash.slice(0, 12)}...</code></td><td><span className={row.status === 'PRESERVED' ? 'status-pill' : 'status-pill warn'}>{row.status}</span></td><td><button className="text-button" type="button" onClick={() => { selectItem(row); setMessage('') }}>Inspect</button></td></tr>)}</tbody></table>{items.length === 0 && <p className="empty-state">No evidence items match this filter.</p>}</div>
            {totals.totalPages > 1 && <div className="pager"><button className="action" type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} of {totals.totalPages} — {totals.totalElements} items</span><button className="action" type="button" disabled={page + 1 >= totals.totalPages} onClick={() => setPage(page + 1)}>Next</button></div>}
        </article>
        <aside className="panel detail-panel"><p className="panel-label">GET /api/evidence-items/{'{id}'}</p><h2>Inspect preserved metadata</h2><p className="panel-copy">Evidence bytes are not returned here. Inspect a row above, or resolve a repository ID directly.</p><form className="lookup-form" onSubmit={lookup}><input required placeholder="Evidence item ID" value={lookupId} onChange={(event) => setLookupId(event.target.value)} /><button className="action" type="submit">Inspect item</button></form>{message && <p className="form-message">{message}</p>}{item && <div className="detail-block"><span className="detail-kicker">{item.status}</span><strong>{item.sourceArtifactId ?? 'Manual preservation'}</strong><dl><dt>Repository ID</dt><dd>{item.id}</dd><dt>Coverage</dt><dd>{formatWindow(item.eventStart, item.eventEnd)}</dd><dt>Created</dt><dd>{formatDate(item.createdAt)}</dd><dt>SHA-256</dt><dd><code>{item.currentHash}</code></dd><dt>Source</dt><dd>{item.evidenceSourceId ?? 'Manual preservation'}</dd></dl></div>}</aside>
        <article className="panel custody-panel"><div className="panel-header"><div><p className="panel-label">GET /api/evidence-items/{'{id}'}/custody</p><h2>Chain of custody</h2></div><span className="chip">{custody.length} entries</span></div><p className="panel-copy">Read the append-only ledger for the selected artifact, then verify its links independently.</p>{item ? <div className="toolbar"><button className="action" type="button" onClick={() => void loadCustody(item.id)}>Refresh chain</button><button className="action" type="button" onClick={() => void verifyCustody()}>Verify chain</button><button className="action primary" type="button" onClick={() => void checkIntegrity()}>Check artifact integrity</button></div> : <p className="empty-state">Inspect an evidence item to view its custody history.</p>}{custodyMessage && <p className="form-message">{custodyMessage}</p>}{verification && <div className={`verification ${verification.intact ? 'verification-good' : 'verification-bad'}`}><strong>{verification.intact ? 'Chain intact' : verification.missingOrigin ? 'Missing origin' : `Chain diverges at sequence ${verification.firstDivergentSequence}`}</strong><span>{verification.length} entries checked{verification.headEntryHash ? ` • head ${verification.headEntryHash.slice(0, 12)}...` : ''}</span></div>}{integrity && <div className={`verification ${integrity.intact ? 'verification-good' : 'verification-bad'}`}><strong>{integrity.intact ? 'Artifact integrity confirmed' : 'Artifact integrity mismatch'}</strong><span>Expected <code>{integrity.expectedHash.slice(0, 16)}...</code> / observed <code>{integrity.observedHash.slice(0, 16)}...</code></span></div>}<div className="event-table-wrap"><table><thead><tr><th>Seq</th><th>Action</th><th>Performed by</th><th>Occurred</th><th>Entry hash</th><th>Detail</th></tr></thead><tbody>{custody.map((entry) => <tr key={entry.id}><td>{entry.sequence}</td><td><span className={entry.action === 'HASH_MISMATCH' ? 'status-pill warn' : 'status-pill'}>{entry.action}</span></td><td>{entry.performedBy ?? 'Ingestion pipeline'}</td><td>{formatDate(entry.occurredAt)}</td><td><code>{entry.entryHash.slice(0, 12)}...</code></td><td>{entry.detail}</td></tr>)}</tbody></table></div></article>
        <article className="panel wide-panel"><div className="panel-header"><div><p className="panel-label">POST /api/evidence-items</p><h2>Preserve an evidence item</h2></div><span className="chip secure">Integrity checked</span></div><p className="panel-copy">Upload an artifact with its source metadata. The repository verifies the source SHA-256 before and after storage.</p><form className="resource-form upload-form" onSubmit={preserve}><input required placeholder="Registered source key" value={form.sourceKey} onChange={(event) => setForm({ ...form, sourceKey: event.target.value })} /><input required placeholder="Source artifact ID" value={form.sourceArtifactId} onChange={(event) => setForm({ ...form, sourceArtifactId: event.target.value })} /><label>Coverage starts<input required type="datetime-local" value={form.eventStart} onChange={(event) => setForm({ ...form, eventStart: event.target.value })} /></label><label>Coverage ends<input required type="datetime-local" value={form.eventEnd} onChange={(event) => setForm({ ...form, eventEnd: event.target.value })} /></label><input required pattern="[a-f0-9]{64}" placeholder="Source SHA-256 (64 lower-case hex characters)" value={form.sourceSha256} onChange={(event) => setForm({ ...form, sourceSha256: event.target.value })} /><label className="file-field">Artifact file<input required type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label><button className="action primary" type="submit">Preserve item</button></form></article>
    </section>
}
