import React from "react";
import forge from "node-forge";
// You can fetch the public key from server or import as string

const LoginForm = () => {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [message, setMessage] = React.useState("");

  const encryptPassword = async (password) => {
    const res = await fetch("/public.pem");
    const publicKeyPem = await res.text(); // getting publicKeyPem

    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const encrypted = publicKey.encrypt(password, "RSA-OAEP", {
      md: forge.md.sha256.create(),
    });
    return forge.util.encode64(encrypted); // send as base64
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const encryptedPwd = encryptPassword(password);

      const res = await fetch("http://localhost:3001/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password: encryptedPwd }),
      });

      const data = await res.json();
      setMessage(data.success ? "Login successful!" : "Login failed");
    } catch (err) {
      console.error(err);
      setMessage("Error connecting to server");
    }
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center",
        width: "100vw",
        height: "84vh",
        border: "1px solid white",
      }}
    >
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: "10px" }}>
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={{ width: "100%", padding: "5px" }}
          />
        </div>
        <div style={{ marginBottom: "10px" }}>
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: "100%", padding: "5px" }}
          />
        </div>
        <button type="submit" style={{ padding: "10px 20px" }}>
          Login
        </button>
      </form>
      {message && <p>{message}</p>}
    </div>
  );
};

export default LoginForm;
