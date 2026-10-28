import { type FormEvent, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { repositoryApi, sha256Hex, type CustodyChainVerification, type CustodyEvent, type EvidenceItem, type IntegrityCheckResult, type WorkGroup } from '../api/api'

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

/** What the browser found when it re-hashed a download, shown beside the custody chain. */
type DownloadCheck = {
    fileName: string
    size: number
    // Null when the browser could not hash (no Web Crypto outside a secure context).
    observed: string | null
    matches: boolean | null
}

/** Hands a blob to the browser as a file download. */
function saveBlob(blob: Blob, fileName: string) {
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = fileName
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
}

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
    const [message, setMessage] = useState('')
    const [custody, setCustody] = useState<CustodyEvent[]>([])
    const [verification, setVerification] = useState<CustodyChainVerification | null>(null)
    const [integrity, setIntegrity] = useState<IntegrityCheckResult | null>(null)
    const [custodyMessage, setCustodyMessage] = useState('')
    const [downloadCheck, setDownloadCheck] = useState<DownloadCheck | null>(null)
    // ?item=<id> opens one item directly, e.g. from "Open item" in an incident's bundle.
    const [searchParams] = useSearchParams()
    const linkedItemId = searchParams.get('item')

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

    // The item may be on any page of the listing, or filtered out of it, so it is fetched by
    // id rather than looked for in the table.
    useEffect(() => {
        if (!linkedItemId) return
        setLookupId(linkedItemId)
        repositoryApi.getEvidenceItem(linkedItemId)
            .then((linked) => { selectItem(linked); setMessage('') })
            .catch((exception) => setMessage(exception instanceof Error ? exception.message : 'Evidence item was not found.'))
    }, [linkedItemId])

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
        setDownloadCheck(null)
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

    /**
     * The server re-hashes before releasing and records the release; the browser hashes what
     * arrived and compares it with the digest on the item, so the copy is checked at both
     * ends. A copy that fails here is not saved.
     */
    async function download() {
        if (!item || !window.confirm('Download this artifact? The release is recorded in its chain of custody.')) return
        try {
            const received = await repositoryApi.downloadEvidenceItem(item.id)
            const observed = crypto?.subtle ? await sha256Hex(received.blob) : null
            // The bytes against the item's recorded digest, and against the digest the server
            // says it sent when that header came through.
            const matches = observed === null ? null
                : observed === item.currentHash && (received.sha256 === null || received.sha256 === observed)
            setDownloadCheck({ fileName: received.fileName, size: received.blob.size, observed, matches })
            if (matches === false) {
                setCustodyMessage('The received copy does not match the recorded digest, so it was not saved.')
            } else {
                saveBlob(received.blob, received.fileName)
                setCustodyMessage('Artifact released and recorded in the custody chain as EXPORTED.')
            }
        } catch (exception) {
            setDownloadCheck(null)
            setCustodyMessage(exception instanceof Error ? exception.message : 'Unable to download the artifact.')
        }
        // Refreshed whatever happened: a release appends EXPORTED, and a refusal appends
        // HASH_MISMATCH and moves the item to COMPROMISED.
        await loadCustody(item.id)
        try { setItem(await repositoryApi.getEvidenceItem(item.id)) } catch { /* keep the item shown */ }
        void load()
    }

    return <section className="workspace-grid item-grid">
        <article className="panel wide-panel scroll-panel sticky-panel">
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
            {/* Five narrow columns so Inspect stays in view: the repository id is on the
                inspect panel, and each date pair stacks rather than sitting side by side. */}
            <div className="event-table-wrap scroll-body"><table className="compact-table"><thead><tr><th>Artifact</th><th className="wide-only">Coverage</th><th className="wide-only">Digest</th><th>Status</th><th /></tr></thead><tbody>{items.map((row) => <tr key={row.id} className={item?.id === row.id ? 'selected-row' : undefined}>
                <td><strong>{row.sourceArtifactId ?? 'Manual preservation'}</strong><small>Preserved {formatDate(row.createdAt)}</small></td>
                <td className="wide-only">{row.eventStart && row.eventEnd ? <>{formatDate(row.eventStart)}<small>to {formatDate(row.eventEnd)}</small></> : 'Not asserted'}</td>
                <td className="wide-only"><code>{row.currentHash.slice(0, 12)}...</code></td>
                <td><span className={row.status === 'PRESERVED' ? 'status-pill' : 'status-pill warn'}>{row.status}</span></td>
                <td><button className="text-button" type="button" onClick={() => { selectItem(row); setMessage('') }}>Inspect</button></td>
            </tr>)}</tbody></table>{items.length === 0 && <p className="empty-state">No evidence items match this filter.</p>}</div>
            {totals.totalPages > 1 && <div className="pager"><button className="action" type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} of {totals.totalPages} — {totals.totalElements} items</span><button className="action" type="button" disabled={page + 1 >= totals.totalPages} onClick={() => setPage(page + 1)}>Next</button></div>}
        </article>
        {/* Inspect and custody share the right column, so the selected item's metadata and its
            ledger read top to bottom beside the list it was chosen from. */}
        <div className="item-side">
            <aside className="panel detail-panel"><p className="panel-label">GET /api/evidence-items/{'{id}'}</p><h2>Inspect preserved metadata</h2><p className="panel-copy">Metadata and digest only. The bytes are released from the custody panel, re-hashed first and recorded as an export.</p><form className="lookup-form" onSubmit={lookup}><input required placeholder="Evidence item ID" value={lookupId} onChange={(event) => setLookupId(event.target.value)} /><button className="action" type="submit">Inspect item</button></form>{message && <p className="form-message">{message}</p>}{item && <div className="detail-block"><span className="detail-kicker">{item.status}</span><strong>{item.sourceArtifactId ?? 'Manual preservation'}</strong><dl><dt>Repository ID</dt><dd>{item.id}</dd><dt>Coverage</dt><dd>{formatWindow(item.eventStart, item.eventEnd)}</dd><dt>Created</dt><dd>{formatDate(item.createdAt)}</dd><dt>SHA-256</dt><dd><code>{item.currentHash}</code></dd><dt>Source</dt><dd>{item.evidenceSourceId ?? 'Manual preservation'}</dd></dl></div>}</aside>
            <article className="panel custody-panel"><div className="panel-header"><div><p className="panel-label">GET /api/evidence-items/{'{id}'}/custody</p><h2>Chain of custody</h2></div><span className="chip">{custody.length} entries</span></div><p className="panel-copy">Read the append-only ledger for the selected artifact, then verify its links independently.</p>{item ? <div className="toolbar"><button className="action" type="button" onClick={() => void loadCustody(item.id)}>Refresh chain</button><button className="action" type="button" onClick={() => void verifyCustody()}>Verify chain</button><button className="action primary" type="button" onClick={() => void checkIntegrity()}>Check artifact integrity</button><button className="action primary" type="button" onClick={() => void download()}>Download (verified)</button></div> : <p className="empty-state">Inspect an evidence item to view its custody history.</p>}{custodyMessage && <p className="form-message">{custodyMessage}</p>}{verification && <div className={`verification ${verification.intact ? 'verification-good' : 'verification-bad'}`}><strong>{verification.intact ? 'Chain intact' : verification.missingOrigin ? 'Missing origin' : `Chain diverges at sequence ${verification.firstDivergentSequence}`}</strong><span>{verification.length} entries checked{verification.headEntryHash ? ` • head ${verification.headEntryHash.slice(0, 12)}...` : ''}</span></div>}{integrity && <div className={`verification ${integrity.intact ? 'verification-good' : 'verification-bad'}`}><strong>{integrity.intact ? 'Artifact integrity confirmed' : 'Artifact integrity mismatch'}</strong><span>Expected <code>{integrity.expectedHash.slice(0, 16)}...</code> / observed <code>{integrity.observedHash.slice(0, 16)}...</code></span></div>}{downloadCheck && <div className={`verification ${downloadCheck.matches === false ? 'verification-bad' : 'verification-good'}`}><strong>{downloadCheck.matches === null ? 'Downloaded (not re-hashed in this browser)' : downloadCheck.matches ? 'Download verified on receipt' : 'Downloaded copy does not match'}</strong><span>{downloadCheck.fileName} • {downloadCheck.size} bytes{downloadCheck.observed ? <> • SHA-256 <code>{downloadCheck.observed.slice(0, 16)}...</code></> : null}</span></div>}<ol className="custody-list">{custody.map((entry) => <li key={entry.id}>
                <div className="custody-entry-head"><span className="custody-seq">#{entry.sequence}</span><span className={entry.action === 'HASH_MISMATCH' ? 'status-pill warn' : 'status-pill'}>{entry.action}</span><small>{formatDate(entry.occurredAt)}</small></div>
                <small>{entry.performedBy ?? 'Ingestion pipeline'} • entry <code>{entry.entryHash.slice(0, 12)}...</code></small>
                <p>{entry.detail}</p>
            </li>)}</ol></article>
        </div>
    </section>
}
