import { FormEvent, useState } from 'react'
import { repositoryApi, type EvidenceItem } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

export default function EvidenceItemsPage() {
    const [lookupId, setLookupId] = useState('')
    const [item, setItem] = useState<EvidenceItem | null>(null)
    const [file, setFile] = useState<File | null>(null)
    const [form, setForm] = useState({ sourceKey: '', sourceArtifactId: '', eventStart: '', eventEnd: '', sourceSha256: '' })
    const [message, setMessage] = useState('')

    async function lookup(event: FormEvent) {
        event.preventDefault()
        try { setItem(await repositoryApi.getEvidenceItem(lookupId)); setMessage('') }
        catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Evidence item was not found.') }
    }

    async function preserve(event: FormEvent) {
        event.preventDefault()
        if (!file) { setMessage('Choose an artifact file before preserving it.'); return }
        try {
            const preserved = await repositoryApi.preserveEvidenceItem({ ...form, eventStart: new Date(form.eventStart).toISOString(), eventEnd: new Date(form.eventEnd).toISOString() }, file)
            setItem(preserved)
            setMessage('Evidence item preserved and verified.')
        } catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Evidence item could not be preserved.') }
    }

    return <section className="workspace-grid item-grid">
        <article className="panel wide-panel"><div className="panel-header"><div><p className="panel-label">POST /api/evidence-items</p><h2>Preserve an evidence item</h2></div><span className="chip secure">Integrity checked</span></div><p className="panel-copy">Upload an artifact with its source metadata. The repository verifies the source SHA-256 before and after storage.</p><form className="resource-form upload-form" onSubmit={preserve}><input required placeholder="Registered source key" value={form.sourceKey} onChange={(event) => setForm({ ...form, sourceKey: event.target.value })} /><input required placeholder="Source artifact ID" value={form.sourceArtifactId} onChange={(event) => setForm({ ...form, sourceArtifactId: event.target.value })} /><label>Coverage starts<input required type="datetime-local" value={form.eventStart} onChange={(event) => setForm({ ...form, eventStart: event.target.value })} /></label><label>Coverage ends<input required type="datetime-local" value={form.eventEnd} onChange={(event) => setForm({ ...form, eventEnd: event.target.value })} /></label><input required pattern="[a-f0-9]{64}" placeholder="Source SHA-256 (64 lower-case hex characters)" value={form.sourceSha256} onChange={(event) => setForm({ ...form, sourceSha256: event.target.value })} /><label className="file-field">Artifact file<input required type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label><button className="action primary" type="submit">Preserve item</button></form></article>
        <aside className="panel detail-panel"><p className="panel-label">GET /api/evidence-items/{'{id}'}</p><h2>Inspect preserved metadata</h2><p className="panel-copy">Evidence bytes are not returned here. Use the repository ID to inspect its custody metadata and digest.</p><form className="lookup-form" onSubmit={lookup}><input required placeholder="Evidence item ID" value={lookupId} onChange={(event) => setLookupId(event.target.value)} /><button className="action" type="submit">Inspect item</button></form>{message && <p className="form-message">{message}</p>}{item && <div className="detail-block"><span className="detail-kicker">{item.status}</span><strong>{item.sourceArtifactId}</strong><dl><dt>Repository ID</dt><dd>{item.id}</dd><dt>Created</dt><dd>{formatDate(item.createdAt)}</dd><dt>SHA-256</dt><dd><code>{item.currentHash}</code></dd><dt>Source</dt><dd>{item.evidenceSourceId ?? 'Manual preservation'}</dd></dl></div>}</aside>
    </section>
}
