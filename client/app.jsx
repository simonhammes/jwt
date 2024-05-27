import React, { useState } from 'react';
import ReactDOM from 'react-dom/client';

document.addEventListener('DOMContentLoaded', () => {
    const root = ReactDOM.createRoot(document.getElementById('root'));
    root.render(<App />);
});

function App() {
    const [accessToken, setAccessToken] = useState(null);
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [hiddenContent, setHiddenContent] = useState("");

    const handleSubmit = async (e) => {
        e.preventDefault();

        const body = { username, password };

        const response = await fetch("http://127.0.0.1:3000/login", {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        })

        if (!response.ok) {
            return;
        }

        const data = await response.json();

        console.log(data)

        setAccessToken(data.access_token)
    }

    const fetchProtectedContent = async () => {
        const response = await fetch("http://127.0.0.1:3000/protected", {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            },
        });

        const content = await response.text();

        setHiddenContent(content);
    }

    return accessToken === null ? (
        <form onSubmit={handleSubmit}>
            <span>Login</span>
            <input
                type="text"
                placeholder="username"
                onChange={(e) => setUsername(e.target.value)}
            />
            <input
                type="password"
                placeholder="password"
                onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Login</button>
        </form>
    ) : (
        <>
            <span>User has been loggedIn </span>
            <button onClick={fetchProtectedContent}>Fetch content</button>
            {hiddenContent}
        </>
    )
}
