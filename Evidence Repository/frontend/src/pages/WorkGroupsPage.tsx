import { FormEvent, useEffect, useState } from 'react'
import { repositoryApi, type WorkGroup } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

export default function WorkGroupsPage() {
    const [groups, setGroups] = useState<WorkGroup[]>([])
    const [form, setForm] = useState({ name: '', classificationCode: '' })
    const [filter, setFilter] = useState('')
    const [message, setMessage] = useState('')

    async function load() { setGroups(await repositoryApi.listWorkGroups(filter)) }
    useEffect(() => { void load() }, [filter])

    async function create(event: FormEvent) {
        event.preventDefault()
        try { await repositoryApi.createWorkGroup(form.name, form.classificationCode); setForm({ name: '', classificationCode: '' }); setMessage('Work group created.'); void load() }
        catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Work group could not be created.') }
    }

    return <section className="workspace-grid work-groups-grid">
        <article className="panel wide-panel"><div className="panel-header"><div><p className="panel-label">GET /api/work-groups</p><h2>Classification catalogue</h2></div><span className="chip">{groups.length} loaded</span></div><div className="toolbar"><input aria-label="Filter by classification code" placeholder="Filter classification code" value={filter} onChange={(event) => setFilter(event.target.value)} /><button className="action" type="button" onClick={() => void load()}>Refresh</button></div><div className="group-list">{groups.map((group) => <article className="group-row" key={group.id}><div><strong>{group.name}</strong><span>{group.classificationCode}</span></div><small>Created {formatDate(group.createdAt)}</small><button className="text-button" type="button" onClick={() => void repositoryApi.getWorkGroup(group.id).then((item) => setMessage(`${item.name} / ${item.classificationCode}`))}>Inspect</button></article>)}</div></article>
        <aside className="panel detail-panel"><p className="panel-label">POST /api/work-groups</p><h2>Create a classification</h2><p className="panel-copy">The server assigns the ID and creation timestamp. Codes use SCREAMING_SNAKE_CASE.</p><form className="lookup-form classification-form" onSubmit={create}><input required placeholder="Human-readable name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /><input required pattern="[A-Z0-9]+(_[A-Z0-9]+)*" placeholder="CLASSIFICATION_CODE" value={form.classificationCode} onChange={(event) => setForm({ ...form, classificationCode: event.target.value })} /><button className="action primary" type="submit">Create work group</button></form>{message && <p className="form-message">{message}</p>}</aside>
    </section>
}
