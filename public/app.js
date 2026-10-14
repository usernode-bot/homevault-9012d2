/* HomeVault's vault screen: loads /api/vault, renders the meter and the two
 * lists, and handles upload, sharing, copy link, download, delete and
 * report. Sends x-usernode-token on every call when the page has one; at
 * the app's own address the platform's edge adds it for us. */
(function () {
  'use strict';

  var params = new URLSearchParams(location.search);
  var DEMO = params.get('demo') === '1';
  var TOKEN = params.get('token') || '';
  var LIMIT_BYTES = 104857600;

  function $(id) { return document.getElementById(id); }

  var el = {
    username: $('hv-username'),
    demoNote: $('hv-demo-note'),
    arc: $('hv-meter-arc'),
    used: $('hv-used'),
    free: $('hv-free'),
    upload: $('hv-upload'),
    uploadLabel: $('hv-upload-label'),
    fileInput: $('hv-file-input'),
    msg: $('hv-msg'),
    error: $('hv-error'),
    retry: $('hv-retry'),
    empty: $('hv-empty'),
    emptyUpload: $('hv-empty-upload'),
    files: $('hv-files'),
    shared: $('hv-shared'),
    shareSheet: $('hv-share-sheet'),
    sharedSheet: $('hv-shared-sheet'),
  };

  var state = { data: null };
  var shareCurrent = null;
  var sharedCurrent = null;

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({}, opts.headers || {});
    if (TOKEN) opts.headers['x-usernode-token'] = TOKEN;
    return fetch(path, opts);
  }

  /* ── Icons (the drawn screen's own inline SVGs) ── */
  var PAGE_ICON = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h8l5 5v13H6zM14 3v5h5"/></svg>';
  var PIC_ICON = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M21 16l-5-4-9 7"/></svg>';
  var SHARE_ICON = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="12" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 11l8-4M8 13l8 4"/></svg>';

  var IMAGE_RE = /\.(jpe?g|png|gif|webp|avif|svg|heic|bmp)$/i;
  var VIS_LABEL = { only_me: 'Only you', members: 'Vault members', public: 'Public link' };

  function fmt(n) {
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    if (n >= 1024) return Math.round(n / 1024) + ' KB';
    return n + ' B';
  }

  function showMessage(text) {
    el.msg.textContent = text;
    el.msg.hidden = false;
  }
  function hideMessage() { el.msg.hidden = true; }

  /* ── Loading, error and empty states ── */
  var SKELETON_ROW = '<li class="list-row"><span class="ic"><span class="skeleton sk-line sk-ic"></span></span>' +
    '<div class="mid"><p class="n"><span class="skeleton sk-line sk-row"></span></p>' +
    '<p class="tag"><span class="skeleton sk-line sk-tag"></span></p></div></li>';

  function renderLoading() {
    el.arc.setAttribute('stroke-dashoffset', '251');
    el.used.innerHTML = '<span class="skeleton sk-line sk-used"></span>';
    el.free.innerHTML = '<span class="skeleton sk-line sk-free"></span>';
    el.files.innerHTML = SKELETON_ROW + SKELETON_ROW + SKELETON_ROW;
    el.shared.innerHTML = SKELETON_ROW + SKELETON_ROW + SKELETON_ROW;
    el.upload.disabled = true;
    el.uploadLabel.textContent = 'Upload a file';
    el.error.hidden = true;
    el.empty.hidden = true;
    el.demoNote.hidden = true;
  }

  function renderError() {
    el.error.hidden = false;
    el.empty.hidden = true;
    el.demoNote.hidden = true;
    el.upload.hidden = false;
    el.upload.disabled = true;
    el.used.textContent = '';
    el.free.textContent = '';
    el.files.innerHTML = '';
    el.shared.innerHTML = '';
  }

  /* ── Rendering ── */
  function renderMeter(d) {
    var used = d.usedBytes;
    var full = used >= LIMIT_BYTES;
    var frac = Math.min(used / LIMIT_BYTES, 1);
    el.arc.setAttribute('stroke-dashoffset', String(Math.round(251 * (1 - frac))));
    if (full) {
      el.used.textContent = 'Vault full';
      el.free.textContent = fmt(used) + ' used of 100 MB';
    } else {
      el.used.textContent = fmt(used) + ' used';
      el.free.textContent = fmt(LIMIT_BYTES - used) + ' free of 100 MB';
    }
  }

  function row(iconHtml, name, tag, rowButton) {
    var li = document.createElement('li');
    li.className = 'list-row';
    var ic = document.createElement('span');
    ic.className = 'ic';
    ic.innerHTML = iconHtml;
    var mid = document.createElement('div');
    mid.className = 'mid';
    var n = document.createElement('p');
    n.className = 'n';
    n.textContent = name;
    var t = document.createElement('p');
    t.className = 'tag';
    t.textContent = tag;
    mid.appendChild(n);
    mid.appendChild(t);
    li.appendChild(ic);
    li.appendChild(mid);
    if (rowButton) li.appendChild(rowButton);
    return li;
  }

  function shareButton(file) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'sh';
    b.innerHTML = SHARE_ICON;
    b.setAttribute('aria-label', 'Share ' + file.name);
    b.addEventListener('click', function () { openShare(file); });
    return b;
  }

  function render(d) {
    el.username.textContent = d.username || '';
    el.demoNote.hidden = !d.demo;
    renderMeter(d);

    var empty = d.files.length === 0;
    el.empty.hidden = !empty;
    el.upload.hidden = empty; // the empty state's button is the only filled one
    el.upload.disabled = d.usedBytes >= LIMIT_BYTES;
    el.uploadLabel.textContent = 'Upload a file';

    el.files.innerHTML = '';
    d.files.forEach(function (f) {
      el.files.appendChild(row(
        IMAGE_RE.test(f.name) ? PIC_ICON : PAGE_ICON,
        f.name,
        fmt(f.sizeBytes) + ' · ' + VIS_LABEL[f.visibility],
        shareButton(f)
      ));
    });

    el.shared.innerHTML = '';
    if (d.shared.length === 0) {
      var li = document.createElement('li');
      li.className = 'list-row';
      var p = document.createElement('p');
      p.className = 'small muted';
      p.textContent = 'Nothing shared with you yet.';
      li.appendChild(p);
      el.shared.appendChild(li);
    } else {
      d.shared.forEach(function (f) {
        var dl = document.createElement('button');
        dl.type = 'button';
        dl.className = 'btn-secondary';
        dl.textContent = 'Download';
        dl.addEventListener('click', function (e) {
          e.stopPropagation();
          download(f.id, f.name, dl);
        });
        var li = row(
          IMAGE_RE.test(f.name) ? PIC_ICON : PAGE_ICON,
          f.name,
          fmt(f.sizeBytes) + ' · From ' + f.ownerUsername,
          dl
        );
        li.addEventListener('click', function () { openShared(f); });
        el.shared.appendChild(li);
      });
    }
  }

  /* ── Loading the vault ── */
  function load() {
    hideMessage();
    renderLoading();
    api('/api/vault' + (DEMO ? '?demo=1' : ''))
      .then(function (r) { if (!r.ok) throw new Error('vault ' + r.status); return r.json(); })
      .then(function (d) { state.data = d; render(d); })
      .catch(function () { renderError(); });
  }

  /* ── Download ── */
  function download(id, name, btn) {
    if (btn) { btn.disabled = true; }
    api('/api/files/' + id + '/download')
      .then(function (r) { if (!r.ok) throw new Error('download ' + r.status); return r.blob(); })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
      })
      .catch(function () { showMessage('Download failed. Try again.'); })
      .then(function () { if (btn) btn.disabled = false; });
  }

  /* ── Upload ── */
  function pick() { el.fileInput.click(); }
  el.upload.addEventListener('click', pick);
  el.emptyUpload.addEventListener('click', pick);

  el.fileInput.addEventListener('change', function () {
    var file = this.files[0];
    this.value = '';
    if (!file) return;
    var d = state.data;
    var free = d ? d.limitBytes - d.usedBytes : 0;
    if (file.size > free) {
      showMessage(file.name + ' is ' + fmt(file.size) + ' and you have ' + fmt(free) + ' free. Delete a file to make room.');
      return;
    }
    upload(file);
  });

  function upload(file) {
    hideMessage();
    el.uploadLabel.textContent = 'Uploading…';
    el.upload.disabled = true;
    var type = file.type || 'application/octet-stream';
    api('/api/files?name=' + encodeURIComponent(file.name) + '&type=' + encodeURIComponent(type), {
      method: 'POST',
      headers: { 'Content-Type': type },
      body: file,
    }).then(function (r) {
      if (r.status === 413) { showMessage('The vault is full. Delete a file to make room.'); }
      else if (!r.ok) { showMessage('Upload failed. Try again.'); }
      else { load(); return; }
      el.uploadLabel.textContent = 'Upload a file';
      if (state.data) el.upload.disabled = state.data.usedBytes >= LIMIT_BYTES;
    }).catch(function () {
      showMessage('Upload failed. Try again.');
      el.uploadLabel.textContent = 'Upload a file';
      if (state.data) el.upload.disabled = state.data.usedBytes >= LIMIT_BYTES;
    });
  }

  /* ── The share sheet ── */
  function setChoices(v) {
    el.shareSheet.querySelectorAll('.choice').forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-v') === v ? 'true' : 'false');
    });
  }

  function updateLinkRow() {
    var rowEl = $('hv-link-row');
    if (shareCurrent && shareCurrent.visibility === 'public' && shareCurrent.publicToken) {
      $('hv-link').value = location.origin + '/s/' + shareCurrent.publicToken;
      rowEl.hidden = false;
    } else {
      rowEl.hidden = true;
    }
  }

  function openShare(file) {
    shareCurrent = file;
    $('hv-share-name').textContent = file.name;
    setChoices(file.visibility);
    updateLinkRow();
    el.shareSheet.showModal();
  }

  el.shareSheet.querySelectorAll('.choice').forEach(function (b) {
    b.addEventListener('click', function () {
      if (!shareCurrent) return;
      var v = b.getAttribute('data-v');
      if (v === shareCurrent.visibility) return;
      setChoices(v); // optimistic; the list keeps its old row on failure
      api('/api/files/' + shareCurrent.id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ visibility: v }),
      }).then(function (r) {
        if (!r.ok) throw new Error('share ' + r.status);
        return r.json();
      }).then(function (updated) {
        shareCurrent.visibility = updated.visibility;
        shareCurrent.publicToken = updated.publicToken;
        updateLinkRow();
        if (state.data) render(state.data);
      }).catch(function () {
        setChoices(shareCurrent.visibility);
        updateLinkRow();
        showMessage("Couldn't change who can open " + shareCurrent.name + '. It still shares as it did.');
      });
    });
  });

  $('hv-copy').addEventListener('click', function () {
    var input = $('hv-link');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value).then(function () {
        $('hv-copy').textContent = 'Copied';
        setTimeout(function () { $('hv-copy').textContent = 'Copy link'; }, 2000);
      }).catch(function () { input.select(); document.execCommand('copy'); });
    } else {
      input.select();
      document.execCommand('copy');
    }
  });

  $('hv-share-download').addEventListener('click', function () {
    if (shareCurrent) download(shareCurrent.id, shareCurrent.name, this);
  });

  $('hv-share-delete').addEventListener('click', function () {
    if (!shareCurrent) return;
    if (!window.confirm('Delete ' + shareCurrent.name + '? This frees its space at once.')) return;
    var file = shareCurrent;
    api('/api/files/' + file.id, { method: 'DELETE' }).then(function (r) {
      el.shareSheet.close();
      if (!r.ok) { showMessage("Couldn't delete " + file.name + '. Try again.'); if (state.data) render(state.data); }
      else { load(); }
    }).catch(function () {
      el.shareSheet.close();
      showMessage("Couldn't delete " + file.name + '. Try again.');
      if (state.data) render(state.data);
    });
  });

  $('hv-share-close').addEventListener('click', function () { el.shareSheet.close(); });

  /* ── The shared-file sheet ── */
  function openShared(file) {
    sharedCurrent = file;
    $('hv-shared-name').textContent = file.name;
    $('hv-shared-meta').textContent = fmt(file.sizeBytes) + ' · From ' + file.ownerUsername;
    var report = $('hv-shared-report');
    report.textContent = 'Report';
    report.disabled = false;
    el.sharedSheet.showModal();
  }

  $('hv-shared-download').addEventListener('click', function () {
    if (sharedCurrent) download(sharedCurrent.id, sharedCurrent.name, this);
  });

  $('hv-shared-report').addEventListener('click', function () {
    if (!sharedCurrent) return;
    var file = sharedCurrent;
    var btn = this;
    btn.disabled = true;
    api('/api/files/' + file.id + '/report', { method: 'POST' }).then(function (r) {
      if (r.ok) { btn.textContent = 'Reported'; }
      else { btn.disabled = false; showMessage("Couldn't report " + file.name + '. Try again.'); }
    }).catch(function () { btn.disabled = false; showMessage("Couldn't report " + file.name + '. Try again.'); });
  });

  $('hv-shared-close').addEventListener('click', function () { el.sharedSheet.close(); });

  el.retry.addEventListener('click', load);

  load();
})();