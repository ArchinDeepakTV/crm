import React from "react";
import { Link } from "react-router-dom";

const Navbar = () => {
  return (
    <nav
      style={{
        display: "flex",
        justifyContent: "space-evenly",
        alignItems: "center",
        backgroundColor: "#282c34",
        height: "15vh",
        width: "100vw",
      }}
    >
      <Link
        to="/"
        style={{
          color: "#61dafb",
          marginRight: "20px",
          textDecoration: "none",
        }}
      >
        Home
      </Link>
      <Link to="/login" style={{ color: "#61dafb", textDecoration: "none" }}>
        Login
      </Link>
    </nav>
  );
};

export default Navbar;
