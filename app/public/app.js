// Client-side behaviour for TeamNotes. Served as a file (not inline) so a strict CSP can forbid inline scripts.
(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;

  async function send(method, url, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
  }

  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(loginForm));
      const response = await send('POST', '/api/login', data);
      if (response.ok) {
        window.location.href = '/notes';
      } else {
        const { error } = await response.json();
        loginForm.querySelector('[role="alert"]').textContent = error;
      }
    });
  }

  const noteForm = document.getElementById('note-form');
  if (noteForm) {
    noteForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = new FormData(noteForm);
      const response = await send('POST', '/api/notes', {
        title: data.get('title'),
        body: data.get('body'),
        private: data.get('private') === 'on',
      });
      if (response.ok) window.location.reload();
    });
  }

  const logout = document.getElementById('logout');
  if (logout) {
    logout.addEventListener('click', async () => {
      await send('POST', '/api/logout');
      window.location.href = '/login';
    });
  }
})();
