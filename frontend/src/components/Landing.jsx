import React from "react";

const Landing = () => {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        width: "100vw",
        height: "100vh",
        flexDirection: "column",
      }}
    >
      <h1>Welcome to the Landing Page</h1>
      <br />
      <p>
        Go to <a href="/login">Login</a> to continue
      </p>
    </div>
  );
};

export default Landing;
