(() => {
  'use strict';

  const INFO_COMMAND = './info';
  const CHANNELS = Object.freeze({
    bugcod3: Object.freeze({ label: 'BugCod3', url: 'https://www.t.me/BugCod3' }),
    rootAccessClub: Object.freeze({ label: 'RootAccessClub', url: 'https://www.t.me/RootAccessClub' })
  });
  const page = document.querySelector('#page-community');
  if (!page) return;

  // The published main app still binds its previous Community IDs at startup.
  // Keep those inert hooks inside this page so the shared app.js can remain untouched.
  function addLegacyAppHooks() {
    if (document.querySelector('#telegram-cta')) return;
    const bridge = document.createElement('div');
    bridge.hidden = true;
    bridge.setAttribute('aria-hidden', 'true');
    bridge.dataset.communityLegacyHooks = 'true';

    const output = document.createElement('p');
    output.className = 'terminal-output';
    const command = document.createElement('code');
    command.id = 'terminal-command';
    output.append(command);

    const status = document.createElement('p');
    status.id = 'terminal-status';
    status.className = 'terminal-status';
    status.hidden = true;

    const cta = document.createElement('a');
    cta.id = 'telegram-cta';
    cta.href = 'https://t.me/RootAccessClub';
    cta.textContent = 'Legacy Community action';

    const announcement = document.createElement('p');
    announcement.id = 'terminal-announcement';
    announcement.setAttribute('role', 'status');
    announcement.setAttribute('aria-live', 'polite');
    announcement.setAttribute('aria-atomic', 'true');

    bridge.append(output, status, cta, announcement);
    page.append(bridge);
  }
  addLegacyAppHooks();

  const commandLine = page.querySelector('#info-command-line');
  const commandOutput = page.querySelector('#info-command');
  const typingCaret = page.querySelector('#typing-caret');
  const infoOutput = page.querySelector('#terminal-info');
  const idlePrompt = page.querySelector('#idle-prompt');
  const actionSession = page.querySelector('#action-session');
  const actionCommand = page.querySelector('#action-command');
  const actionStatus = page.querySelector('#action-status');
  const actions = [...page.querySelectorAll('[data-community]')];
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  let readyTimer = 0;
  let typingTimer = 0;
  let outputTimer = 0;
  let navigationTimer = 0;
  let typingIndex = 0;
  let active = false;
  let navigating = false;

  function clearTimers() {
    window.clearTimeout(readyTimer);
    window.clearTimeout(typingTimer);
    window.clearTimeout(outputTimer);
    window.clearTimeout(navigationTimer);
    readyTimer = typingTimer = outputTimer = navigationTimer = 0;
  }

  function reset() {
    clearTimers();
    typingIndex = 0;
    navigating = false;
    commandLine.hidden = false;
    commandOutput.textContent = '';
    typingCaret.hidden = false;
    infoOutput.hidden = true;
    idlePrompt.hidden = true;
    actionSession.hidden = true;
    actionCommand.textContent = '';
    actionStatus.textContent = '';
    actions.forEach((button) => { button.disabled = true; });
  }

  function finishInfo() {
    readyTimer = 0;
    typingTimer = 0;
    outputTimer = 0;
    commandOutput.textContent = INFO_COMMAND;
    typingCaret.hidden = true;
    infoOutput.hidden = false;
    idlePrompt.hidden = false;
    actions.forEach((button) => { button.disabled = false; });
  }

  function typeNextCharacter() {
    typingIndex += 1;
    commandOutput.textContent = INFO_COMMAND.slice(0, typingIndex);
    if (typingIndex >= INFO_COMMAND.length) {
      outputTimer = window.setTimeout(finishInfo, 120);
      return;
    }
    typingTimer = window.setTimeout(typeNextCharacter, 39);
  }

  function enter() {
    if (active || page.hidden) return;
    active = true;
    reset();
    if (reducedMotion.matches) {
      finishInfo();
      return;
    }
    readyTimer = window.setTimeout(typeNextCharacter, 150);
  }

  function leave() {
    if (!active) return;
    active = false;
    reset();
  }

  function syncPageVisibility() {
    if (page.hidden) leave();
    else enter();
  }

  function openCommunity(button) {
    if (!active || navigating || button.disabled) return;
    const channel = CHANNELS[button.dataset.community];
    if (!channel) return;

    navigating = true;
    actions.forEach((candidate) => { candidate.disabled = true; });
    idlePrompt.hidden = true;
    actionSession.hidden = false;
    actionCommand.textContent = `xdg-open "${channel.url}"`;
    actionStatus.textContent = `Opening ${channel.url}...`;
    navigationTimer = window.setTimeout(() => {
      if (!active || !navigating) return;
      window.location.assign(channel.url);
    }, 950);
  }

  actions.forEach((button) => button.addEventListener('click', () => openCommunity(button)));
  window.addEventListener('subzero:pagechange', syncPageVisibility);

  // The existing app changes the page's hidden attribute but does not emit the
  // lifecycle event used by the isolated preview. Observe this page only.
  const visibilityObserver = new MutationObserver(syncPageVisibility);
  visibilityObserver.observe(page, { attributes: true, attributeFilter: ['hidden'] });

  window.addEventListener('pageshow', (event) => {
    if (!event.persisted || page.hidden) return;
    active = false;
    enter();
  });

  if (!page.hidden) enter();
})();
