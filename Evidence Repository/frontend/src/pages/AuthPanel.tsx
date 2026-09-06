import { FormEvent, useState } from 'react'
import { clearCredentials, repositoryApi, setCredentials } from '../api/api'

export default function AuthPanel({ onAuthenticated }: { onAuthenticated: () => void }) {
    const [username, setUsername] = useState('admin')
    const [password, setPassword] = useState('admin')
    const [error, setError] = useState('')

    async function submit(event: FormEvent) {
        event.preventDefault()
        setCredentials(username, password)
        try {
            await repositoryApi.listWorkGroups()
            onAuthenticated()
        } catch {
            clearCredentials()
            setError('Credentials were rejected by the repository.')
        }
    }

    return <section className="panel auth-panel">
        <p className="panel-label">Connection required</p>
        <h2>Sign in to the repository</h2>
        <p className="panel-copy">The API uses HTTP Basic authentication in local development.</p>
        <form className="auth-form" onSubmit={submit}>
            <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            <button className="action primary" type="submit">Connect</button>
        </form>
        {error && <p className="error-message">{error}</p>}
    </section>
}
