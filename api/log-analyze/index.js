const { analyzeWindows, analyzeSalesforce } = require('./engine');

module.exports = async function (context, req) {
  try {
    const body = req.body || {};
    const mode = body.mode;

    if (mode === 'windows') {
      const text = body.text;
      if (!text || !text.trim()) {
        context.res = { status: 400, body: { error: 'text is required for mode=windows' } };
        return;
      }
      const findings = analyzeWindows(text);
      context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: { findings } };
      return;
    }

    if (mode === 'salesforce') {
      const rows = body.rows;
      if (!rows || !rows.length) {
        context.res = { status: 400, body: { error: 'rows is required for mode=salesforce' } };
        return;
      }
      const findings = analyzeSalesforce(rows);
      context.res = { status: 200, headers: { 'Content-Type': 'application/json' }, body: { findings } };
      return;
    }

    context.res = { status: 400, body: { error: "mode must be 'windows' or 'salesforce'" } };
  } catch (err) {
    context.log.error(err);
    context.res = { status: 500, body: { error: 'Analysis failed: ' + err.message } };
  }
};
