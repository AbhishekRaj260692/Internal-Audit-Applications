const { runOracleServer, getOracleVocab, resolveRolesToPrivileges, runOracleQuickCheck } = require('./oracle-engine');
const { runMyComServer, getMyComVocab, runMyComQuickCheck } = require('./mycom-engine');

module.exports = async function (context, req) {
  try {
    const body = req.body || {};
    const system = body.system;
    const mode = body.mode; // undefined = bulk analysis (existing behavior)

    // ── VOCAB — autocomplete lists only (privilege/window names, role
    // display names). Never returns the role→privilege mapping itself. ──
    if (mode === 'vocab') {
      if (system === 'oracle') {
        context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: getOracleVocab() };
        return;
      }
      if (system === 'mycom') {
        context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: getMyComVocab() };
        return;
      }
      context.res = { status: 400, body: { error: "system must be 'oracle' or 'mycom'" } };
      return;
    }

    // ── SINGLE-USER QUICK CHECK ──────────────────────────────────
    if (mode === 'quickcheck') {
      if (system === 'oracle') {
        let privileges = body.privileges || [];
        let resolvedInfo = null;
        if (body.roles && body.roles.length) {
          const resolved = resolveRolesToPrivileges(body.roles);
          privileges = resolved.privileges;
          resolvedInfo = { resolvedCount: resolved.privileges.length, unresolved: resolved.unresolved };
        }
        if (!privileges.length) {
          context.res = { status: 400, body: { error: 'privileges or roles is required for quickcheck' } };
          return;
        }
        const findings = runOracleQuickCheck(privileges);
        context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: { findings, resolvedInfo } };
        return;
      }
      if (system === 'mycom') {
        const rows = body.rows || [];
        if (!rows.length) {
          context.res = { status: 400, body: { error: 'rows is required for quickcheck' } };
          return;
        }
        const findings = runMyComQuickCheck(rows, body.options || {});
        context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: { findings } };
        return;
      }
      context.res = { status: 400, body: { error: "system must be 'oracle' or 'mycom'" } };
      return;
    }

    // ── BULK ANALYSIS (existing behavior, unchanged) ─────────────
    if (system === 'oracle') {
      const { userRoles, rolePrivs } = body;
      if (!userRoles || !rolePrivs) {
        context.res = { status: 400, body: { error: 'userRoles and rolePrivs are required for system=oracle' } };
        return;
      }
      const result = runOracleServer(userRoles, rolePrivs);
      context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
      return;
    }

    if (system === 'mycom') {
      if (!body.layout) {
        context.res = { status: 400, body: { error: 'layout is required for system=mycom (direct|groups|multi)' } };
        return;
      }
      const result = runMyComServer(body);
      context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
      return;
    }

    context.res = { status: 400, body: { error: "system must be 'oracle' or 'mycom'" } };
  } catch (err) {
    context.log.error(err);
    context.res = { status: 500, body: { error: 'Analysis failed: ' + err.message } };
  }
};
