import { type FormEvent, useEffect, useState } from 'react'
import { repositoryApi, type EvidenceLink, type Incident, type LinkDisposition } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

function formatWindow(start: string | null, end: string | null) {
    if (!start || !end) return 'Not asserted'
    return `${formatDate(start)} — ${formatDate(end)}`
}

type Review = { link: EvidenceLink; ruling: 'confirm' | 'dismiss' }

/**
 * One incident's bundle, and the place an investigator rules on it.
 *
 * Every ruling needs a reason, and a link can be ruled on once: the backend refuses a second
 * review rather than overwrite the first, so there is no "undo" here to offer.
 */
export default function EvidenceBundlePanel({ incident, onReviewed }: { incident: Incident, onReviewed?: () => void }) {
    const [links, setLinks] = useState<EvidenceLink[]>([])
    const [disposition, setDisposition] = useState<LinkDisposition | ''>('')
    const [review, setReview] = useState<Review | null>(null)
    const [reason, setReason] = useState('')
    const [error, setError] = useState('')

    async function load() {
        try { setLinks((await repositoryApi.listIncidentLinks(incident.id, disposition)).content); setError('') }
        catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load the bundle.') }
    }

    useEffect(() => { setReview(null); void load() }, [incident.id, disposition])

    async function submit(formEvent: FormEvent) {
        formEvent.preventDefault()
        if (!review) return
        try {
            await repositoryApi.reviewEvidenceLink(review.link.id, review.ruling, reason)
            setReview(null)
            setReason('')
            void load()
            onReviewed?.()
        } catch (exception) {
            // Most often a 409: someone else ruled on this link first. Reload so the table
            // shows the ruling that stands.
            setError(exception instanceof Error ? exception.message : 'The review was not recorded.')
            void load()
        }
    }

    const pending = incident.correlationStatus === 'PENDING' || incident.correlationStatus === 'FAILED'

    return <article className="panel wide-panel">
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
        {error && <p className="error-message">{error}</p>}
        {review && <form className="review-form" onSubmit={submit}>
            <label>{review.ruling === 'confirm' ? 'Confirm' : 'Dismiss'} {review.link.evidenceItem.sourceArtifactId} — reason (required, kept in the record)
                <textarea required autoFocus rows={3} value={reason} onChange={(change) => setReason(change.target.value)} /></label>
            <div className="toolbar"><button className="action primary" type="submit" disabled={!reason.trim()}>Record {review.ruling === 'confirm' ? 'confirmation' : 'dismissal'}</button><button className="action" type="button" onClick={() => { setReview(null); setReason('') }}>Cancel</button></div>
        </form>}
        <div className="event-table-wrap"><table><thead><tr><th>Evidence</th><th>Coverage</th><th>Proposed by</th><th>Ruling</th><th /></tr></thead><tbody>{links.map((link) => <tr key={link.id}>
            <td><strong>{link.evidenceItem.sourceArtifactId}</strong><small>{link.evidenceSourceKey ?? 'Manual preservation'}</small></td>
            <td>{formatWindow(link.evidenceItem.eventStart, link.evidenceItem.eventEnd)}</td>
            <td>{link.linkMethod}{link.lateArrival && <> <span className="status-pill warn">Late</span></>}<small title={link.rationale ?? ''}>{formatDate(link.linkedAt)}</small></td>
            <td><span className={link.disposition === 'DISMISSED' ? 'status-pill warn' : 'status-pill'}>{link.disposition}</span>{link.reviewedBy && <small title={link.reviewNote ?? ''}>{link.reviewedBy}: {link.reviewNote}</small>}</td>
            <td>{link.disposition === 'PROPOSED' && <><button className="text-button" type="button" onClick={() => { setReview({ link, ruling: 'confirm' }); setReason('') }}>Confirm</button> <button className="text-button" type="button" onClick={() => { setReview({ link, ruling: 'dismiss' }); setReason('') }}>Dismiss</button></>}</td>
        </tr>)}</tbody></table>{links.length === 0 && <p className="empty-state">No links match this filter.</p>}</div>
    </article>
}
