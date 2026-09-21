(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const form = $('mail-form');
  if (!form) return;
  let csrf = '', dirty = false, busy = false, loaded = false;
  const labels = {queued:'En cola', preparing:'Preparando PDF', sending:'Enviando', accepted:'Aceptado por Microsoft', partial:'Aceptado parcialmente', failed:'Falló', uncertain:'Resultado incierto', cancelled:'Cancelado'};
  const kinds = {weekly:'Semanal', test:'Prueba', manual:'Manual'};
  const notice = (text, error = false) => { $('mail-notice').textContent = text; $('mail-notice').classList.toggle('mail-error', error); };
  function transportFields() {
    const graph = $('mail-transport').value === 'graph';
    $('mail-graph-fields').hidden = !graph;
    $('mail-smtp-fields').hidden = graph;
    $('mail-tenant').required = graph;
    $('mail-client').required = graph;
  }
  async function api(path = '', payload) {
    const response = await fetch('/dashboard/api/report-mail' + path, {
      method: payload === undefined ? 'GET' : 'POST', credentials:'same-origin', cache:'no-store',
      headers: payload === undefined ? {} : {'Content-Type':'application/json', 'X-CSRF-Token':csrf},
      body: payload === undefined ? undefined : JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'No se pudo completar la operación.');
    return data;
  }
  function activity(data) {
    const alive = data.worker_heartbeat && Date.now() - Date.parse(data.worker_heartbeat) < 600000;
    $('mail-service').textContent = alive ? 'Servicio de correo activo' : 'Servicio de correo sin señal';
    $('mail-service').classList.toggle('mail-error', !alive);
    $('mail-next').textContent = data.next_due ? 'Próximo envío: ' + new Date(data.next_due).toLocaleString('es', {timeZone:data.config.timezone}) + ' (' + data.config.timezone + ')' : 'Envío automático desactivado.';
    $('mail-history').replaceChildren();
    for (const job of data.jobs) {
      const tr = document.createElement('tr');
      for (const text of [new Date(job.created).toLocaleString(), `${kinds[job.kind] || job.kind} · ${job.start} / ${job.end}`, labels[job.status] || job.status, job.detail || 'Pendiente']) {
        const td = document.createElement('td'); td.textContent = text; tr.append(td);
      }
      $('mail-history').append(tr);
    }
    if (!data.jobs.length) {
      const tr = document.createElement('tr'), td = document.createElement('td');
      td.colSpan = 4; td.textContent = 'Todavía no hay envíos. Guarde su cuenta y envíe una prueba.';
      tr.append(td); $('mail-history').append(tr);
    }
  }
  function populate(data) {
    const c = data.config;
    for (const [id,key] of [['sender','sender'],['transport','transport'],['tenant','tenant_id'],['client','client_id'],['weekday','weekday'],['hour','hour'],['timezone','timezone']]) $('mail-'+id).value = c[key];
    $('mail-recipients').value = c.recipients.join('\n');
    $('mail-enabled').checked = c.enabled;
    $('mail-password').value = ''; $('mail-secret').value = '';
    $('mail-credential-status').textContent = data.has_credentials ? 'Credencial guardada. Escriba una nueva solo si desea sustituirla.' : 'No hay credenciales guardadas.';
    transportFields(); loaded = true; dirty = false;
  }
  async function refresh(fill = false) {
    try {
      const data = await api(); csrf = data.csrf; activity(data);
      if (fill && !dirty) populate(data);
    } catch (e) { notice(e.message, true); }
  }
  async function action(fn) {
    if (busy) return;
    busy = true; for (const button of form.querySelectorAll('button')) button.disabled = true;
    try { await fn(); } catch (e) { notice(e.message, true); }
    finally { busy = false; for (const button of form.querySelectorAll('button')) button.disabled = false; }
  }
  form.addEventListener('input', () => { dirty = true; });
  $('mail-transport').addEventListener('change', transportFields);
  form.addEventListener('submit', event => {
    event.preventDefault();
    action(async () => {
      if (!loaded) throw new Error('Espere a que se cargue la configuración.');
      const payload = {enabled:$('mail-enabled').checked, transport:$('mail-transport').value, sender:$('mail-sender').value.trim(),
        recipients:$('mail-recipients').value.split(/[\n,;]+/).map(x=>x.trim()).filter(Boolean),
        weekday:Number($('mail-weekday').value), hour:$('mail-hour').value, timezone:$('mail-timezone').value.trim(),
        tenant_id:$('mail-tenant').value.trim(), client_id:$('mail-client').value.trim(),
        password:$('mail-password').value, client_secret:$('mail-secret').value};
      const data = await api('', payload); csrf = data.csrf; populate(data); activity(data);
      notice('Configuración guardada. Los cambios se aplican sin reiniciar el servicio de correo.');
    });
  });
  function send(kind) {
    action(async () => {
      if (dirty) throw new Error('Guarde los cambios antes de enviar.');
      await api('/send', {kind}); notice('Envío en cola. Consulte el resultado en Actividad.'); await refresh();
    });
  }
  $('mail-test').addEventListener('click', () => send('test'));
  $('mail-send').addEventListener('click', () => send('manual'));
  $('mail-refresh').addEventListener('click', () => refresh(!loaded));
  refresh(true);
  setInterval(() => { if ($('tab-report-mail').classList.contains('active') && !busy) refresh(!loaded); }, 15000);
})();
