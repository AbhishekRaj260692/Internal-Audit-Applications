const { analysePM, analyseOR } = require('./engine');

module.exports = async function (context, req) {
  try {
    const body = req.body || {};
    const system = body.system;

    if (system === 'pmweb') {
      const { usersRaw, matrix, adminSheet, options } = body;
      if (!usersRaw || !usersRaw.length) {
        context.res = { status: 400, body: { error: 'usersRaw is required for system=pmweb' } };
        return;
      }
      const { res, pmAssessment, govNotes, pmDiagnostic } = analysePM(usersRaw, matrix || [], adminSheet || [], options || {});
      context.res = {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: { results: res, assessment: pmAssessment, govNotes, pmDiagnostic }
      };
      return;
    }

    if (system === 'oracle') {
      const { userRoleRaw, rolePrivRaw, options } = body;
      if (!userRoleRaw || !userRoleRaw.length) {
        context.res = { status: 400, body: { error: 'userRoleRaw is required for system=oracle' } };
        return;
      }
      const { res, orAssessment, orRolePrivCounts, orDirectAdminTop } =
        analyseOR(userRoleRaw, rolePrivRaw || [], options || {});
      context.res = {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: { results: res, assessment: orAssessment, orRolePrivCounts, orDirectAdminTop }
      };
      return;
    }

    context.res = { status: 400, body: { error: "system must be 'pmweb' or 'oracle'" } };
  } catch (err) {
    context.log.error(err);
    context.res = { status: 500, body: { error: 'Analysis failed: ' + err.message } };
  }
};
