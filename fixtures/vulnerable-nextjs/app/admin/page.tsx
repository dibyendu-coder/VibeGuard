'use client';

import React, { useState } from 'react';

export default function AdminDashboardPage() {
  const [user, setUser] = useState({ name: 'Bob', role: 'admin' });

  // Client-side only authorization check
  if (user.role === 'admin') {
    return (
      <div>
        <h1>Admin Control Panel</h1>
        <button onClick={() => alert('Purged database')}>Purge Records</button>
      </div>
    );
  }

  return <div>Access Denied</div>;
}
