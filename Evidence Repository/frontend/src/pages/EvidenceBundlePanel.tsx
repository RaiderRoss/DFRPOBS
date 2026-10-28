import { type FormEvent, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { repositoryApi, type EvidenceLink, type Incident, type LinkDisposition } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

function formatWindow(start: string | null, end: string | null) {
    if (!start || !end) return 'Not asserted'
    return `${formatDate(start)} — ${formatDate(end)}`
}

/** The links one ruling applies to, and how to name them in the reason box. */
type Review = { ids: string[]; ruling: 'confirm' | 'dismiss'; label: string }

/**
 * Which correlation rules proposed a link, read from the "Matched …" sentence the
 * correlation pass writes at the start of an AUTO_RULE link's rationale.
 */
function matchedRules(link: EvidenceLink) {
    const rationale = link.rationale ?? ''
    const rules: string[] = []
    if (rationale.includes('alert-instant')) rules.push('Covers alert time')
    const ips = /artifact mentions (.+?), named by the alert/.exec(rationale)
    if (ips) rules.push(`Mentions ${ips[1]}`)
    return rules
}

/**
 * Links proposed on something stronger than overlap come first; the rest are the ones an
 * investigator usually sets aside together.
 */
const groups: { title: string; note: string; test: (link: EvidenceLink) => boolean }[] = [
    { title: 'Matched by rule', note: 'Covers the moment an alert fired, or mentions the address it names — open these first.', test: (link) => link.linkMethod !== 'AUTO_TIME_WINDOW' },
    { title: 'Time overlap only', note: 'Overlaps the search window and nothing more.', test: (link) => link.linkMethod === 'AUTO_TIME_WINDOW' },
]

/**
 * One incident's bundle, and the place an investigator rules on it.
 *
 * Every ruling needs a reason, and a link can be ruled on once: the backend refuses a second
 * review rather than overwrite the first, so there is no "undo" here to offer. Several links
 * can share one ruling and one reason; each is still recorded as its own review.
 */
export default function EvidenceBundlePanel({ incident, onReviewed }: { incident: Incident, onReviewed?: () => void }) {
    const [links, setLinks] = useState<EvidenceLink[]>([])
    const [disposition, setDisposition] = useState<LinkDisposition | ''>('')
    const [selected, setSelected] = useState<Set<string>>(new Set())
    const [review, setReview] = useState<Review | null>(null)
    const [reason, setReason] = useState('')
    const [error, setError] = useState('')
    const navigate = useNavigate()

    async function load() {
        // 200 is the bulk endpoint's cap, so everything shown can be ruled on in one go.
        try { setLinks((await repositoryApi.listIncidentLinks(incident.id, disposition, 0, 200)).content); setError('') }
        catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load the bundle.') }
    }

    useEffect(() => { setReview(null); setSelected(new Set()); void load() }, [incident.id, disposition])

    function toggle(ids: string[], on: boolean) {
        const next = new Set(selected)
        for (const id of ids) {
            if (on) next.add(id)
            else next.delete(id)
        }
        setSelected(next)
    }

    function startReview(ids: string[], ruling: Review['ruling'], label: string) {
        setReview({ ids, ruling, label })
        setReason('')
    }

    async function submit(formEvent: FormEvent) {
        formEvent.preventDefault()
        if (!review) return
        try {
            if (review.ids.length === 1) await repositoryApi.reviewEvidenceLink(review.ids[0], review.ruling, reason)
            else await repositoryApi.reviewEvidenceLinks(review.ids, review.ruling, reason)
            setReview(null)
            setReason('')
            setSelected(new Set())
            void load()
            onReviewed?.()
        } catch (exception) {
            // Most often a 409: someone else ruled on a link first. A selection is all or
            // none, so nothing in it was recorded; reload so the table shows what stands.
            setError(exception instanceof Error ? exception.message : 'The review was not recorded.')
            setSelected(new Set())
            void load()
        }
    }

    const pending = incident.correlationStatus === 'PENDING' || incident.correlationStatus === 'FAILED'
    const proposedIds = new Set(links.filter((link) => link.disposition === 'PROPOSED').map((link) => link.id))
    const chosen = [...selected].filter((id) => proposedIds.has(id))
    const plural = (count: number) => `${count} link${count === 1 ? '' : 's'}`

    return <article className="panel wide-panel scroll-panel bundle-panel">
        <div className="panel-header"><div><p className="panel-label">GET /api/incidents/{'{id}'}/links</p><h2>Evidence bundle — {incident.incidentKey}</h2></div><span className={pending ? 'status-pill warn' : 'status-pill'}>{incident.correlationStatus}</span></div>
        <p className="panel-copy">{pending
            ? 'This incident has not been correlated yet, so an empty bundle means it has not been searched — not that nothing was found.'
            : incident.correlationStatus === 'CORRELATED'
                ? 'Correlated, but still open: evidence that arrives late is added and flagged.'
                : 'Closed: the collection lag has passed and the bundle is settled. A new alert in this incident reopens it.'}</p>
        <div className="toolbar">
            <select aria-label="Filter by disposition" value={disposition} onChange={(change) => setDisposition(change.target.value as LinkDisposition | '')}>
                <option value="">All links</option>
                <option value="PROPOSED">Unreviewed</option>
                <option value="CONFIRMED">Confirmed</option>
                <option value="DISMISSED">Dismissed</option>
            </select>
            <button className="action" type="button" onClick={() => void load()}>Refresh</button>
        </div>
        {chosen.length > 0 && !review && <div className="selection-bar">
            <strong>{plural(chosen.length)} selected</strong>
            <button className="action primary" type="button" onClick={() => startReview(chosen, 'confirm', plural(chosen.length))}>Confirm selected</button>
            <button className="action" type="button" onClick={() => startReview(chosen, 'dismiss', plural(chosen.length))}>Dismiss selected</button>
            <button className="text-button" type="button" onClick={() => setSelected(new Set())}>Clear</button>
        </div>}
        {error && <p className="error-message">{error}</p>}
        {review && <form className="review-form" onSubmit={submit}>
            <label>{review.ruling === 'confirm' ? 'Confirm' : 'Dismiss'} {review.label} — reason (required, kept in the record{review.ids.length > 1 ? ' on every link' : ''})
                <textarea required autoFocus rows={3} value={reason} onChange={(change) => setReason(change.target.value)} /></label>
            <div className="toolbar"><button className="action primary" type="submit" disabled={!reason.trim()}>Record {review.ruling === 'confirm' ? 'confirmation' : 'dismissal'}{review.ids.length > 1 ? `s (${review.ids.length})` : ''}</button><button className="action" type="button" onClick={() => { setReview(null); setReason('') }}>Cancel</button></div>
        </form>}
        <div className="event-table-wrap scroll-body"><table><thead><tr><th /><th>Evidence</th><th>Coverage</th><th>Proposed by</th><th>Ruling</th><th /></tr></thead>
            {groups.map((group) => {
                const rows = links.filter(group.test)
                if (rows.length === 0) return null
                const open = rows.filter((link) => link.disposition === 'PROPOSED').map((link) => link.id)
                const allChosen = open.length > 0 && open.every((id) => selected.has(id))
                return <tbody key={group.title}>
                    <tr className="group-row-header"><td>{open.length > 0 && <input type="checkbox" aria-label={`Select every unreviewed link in ${group.title}`} checked={allChosen} onChange={(change) => toggle(open, change.target.checked)} />}</td>
                        <td colSpan={5}><strong>{group.title} · {rows.length}</strong><small>{group.note}{open.length > 0 ? ` ${open.length} unreviewed.` : ''}</small></td></tr>
                    {rows.map((link) => <tr key={link.id}>
                        <td>{link.disposition === 'PROPOSED' && <input type="checkbox" aria-label={`Select ${link.evidenceItem.sourceArtifactId}`} checked={selected.has(link.id)} onChange={(change) => toggle([link.id], change.target.checked)} />}</td>
                        <td><strong>{link.evidenceItem.sourceArtifactId}</strong><small>{link.evidenceSourceKey ?? 'Manual preservation'}</small></td>
                        <td>{formatWindow(link.evidenceItem.eventStart, link.evidenceItem.eventEnd)}</td>
                        <td title={link.rationale ?? ''}>{link.linkMethod}{link.lateArrival && <> <span className="status-pill warn">Late</span></>}<small>{matchedRules(link).join(' · ') || formatDate(link.linkedAt)}</small></td>
                        <td><span className={link.disposition === 'DISMISSED' ? 'status-pill warn' : 'status-pill'}>{link.disposition}</span>{link.reviewedBy && <small title={link.reviewNote ?? ''}>{link.reviewedBy}: {link.reviewNote}</small>}</td>
                        <td>{link.disposition === 'PROPOSED' && <><button className="text-button" type="button" onClick={() => startReview([link.id], 'confirm', link.evidenceItem.sourceArtifactId ?? 'this link')}>Confirm</button> <button className="text-button" type="button" onClick={() => startReview([link.id], 'dismiss', link.evidenceItem.sourceArtifactId ?? 'this link')}>Dismiss</button> </>}<button className="text-button" type="button" title="Metadata, custody chain and verified download" onClick={() => navigate(`/evidence-items?${new URLSearchParams({ item: link.evidenceItem.id })}`)}>Open item</button></td>
                    </tr>)}
                </tbody>
            })}
        </table>{links.length === 0 && <p className="empty-state">No links match this filter.</p>}</div>
    </article>
}
