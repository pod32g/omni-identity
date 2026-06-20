import React from "react";
import "./AdminNav.css";
import { cx } from "../../util/cx";
import { Button } from "../Button/Button";

export interface AdminNavLink {
  label: string;
  href: string;
  active?: boolean;
}

export interface AdminNavProps {
  /** Brand text at the left. */
  brand?: string;
  /** Navigation links. */
  links: AdminNavLink[];
  /** Signed-in username shown before the sign-out button. */
  username?: string;
  /** Called when the sign-out button is clicked. */
  onSignOut?: () => void;
  className?: string;
}

/** The admin top bar: brand + nav links on the left, user + sign-out on the right. */
export function AdminNav({ brand = "Omni Identity", links, username, onSignOut, className }: AdminNavProps) {
  return (
    <div className={cx("omni-topbar", className)}>
      <nav className="omni-nav">
        <strong>{brand}</strong>
        {links.map((l) => (
          <a
            key={l.href}
            href={l.href}
            className={cx("omni-nav__link", l.active && "omni-nav__link--active")}
          >
            {l.label}
          </a>
        ))}
      </nav>
      <div className="omni-topbar__end">
        {username ? <span className="omni-topbar__user">{username}</span> : null}
        <Button variant="secondary" onClick={onSignOut}>
          Sign out
        </Button>
      </div>
    </div>
  );
}
