'use strict';

const path = require('path');
const fs = require('fs');
const debug = require('debug')('plugin:mocktillery');

module.exports = {
  Plugin: MocktilleryPlugin
};

function loadSecretFiles(config, propName, basePath) {
    if (config.mocktillery.security[propName]) {
      let filename = path.resolve(basePath, config.mocktillery.security[propName]);
      config.__mocktilleryPlugin[propName] = fs.readFileSync(filename, 'utf8');
    }
  }

function MocktilleryPlugin(script, events, opts) {

  const basePath = path.dirname(opts.absoluteScriptPath);

  script.config.__mocktilleryPlugin = {};

  if (script.config.mocktillery && script.config.mocktillery.security) {
    loadSecretFiles(script.config, 'pfx', basePath);
    loadSecretFiles(script.config, 'key', basePath);
    loadSecretFiles(script.config, 'certificate', basePath);
    loadSecretFiles(script.config, 'ca', basePath);

    script.config.__mocktilleryPlugin["passphrase"] = script.config.mocktillery.security.passphrase;
    script.config.__mocktilleryPlugin["proxy"] = process.env.HTTP_PROXY ? process.env.HTTP_PROXY : script.config.mocktillery.proxy ?  script.config.mocktillery.proxy : undefined;

    if(script.config.mocktillery.security.proxyUser && script.config.mocktillery.security.proxyPassword) {
      script.config.__mocktilleryPlugin["proxyAuthorization"] = 
        `Basic ${Buffer.from(script.config.mocktillery.security.proxyUser + ':' + script.config.mocktillery.security.proxyPassword).toString('base64')}`;
    }

    if (!script.config.processor) {
      script.config.processor = {};
    }

    script.config.processor.mocktilleryPluginCreateVariables = function(
      userContext,
      events,
      done
    ) {
      userContext.vars.pfx = script.config.__mocktilleryPlugin.pfx;
      userContext.vars.key = script.config.__mocktilleryPlugin.key;
      userContext.vars.certificate = script.config.__mocktilleryPlugin.certificate;
      userContext.vars.ca = script.config.__mocktilleryPlugin.ca;
      userContext.vars.passphrase = script.config.__mocktilleryPlugin.passphrase;
      userContext.vars.proxy = script.config.__mocktilleryPlugin.proxy;
      userContext.vars.proxyAuthorization = script.config.__mocktilleryPlugin.proxyAuthorization ? proxyAuthorization : undefined;

      return done();
    };

    script.config.processor.mocktilleryPluginSetOpts = function(
      req,
      userContext,
      events,
      done
    ) {
      if (req.sslAuth !== false) {
        req.key = userContext.vars.key;
        req.cert = userContext.vars.certificate;
        req.ca = userContext.vars.ca;
        req.pfx = userContext.vars.pfx;
        req.passphrase = userContext.vars.passphrase;
        req.proxy = userContext.vars.proxy;

        if(userContext.vars.proxyAuthorization)
          req.headers["Authorization"] = userContext.vars.proxyAuthorization;

      }

      return done();
    };

    script.scenarios.forEach(function(scenario) {
      if (!scenario.beforeScenario) {
        scenario.beforeScenario = [];
      }

      if (!scenario.beforeRequest) {
        scenario.beforeRequest = [];
      }

      scenario.beforeScenario.push('mocktilleryPluginCreateVariables');
      scenario.beforeRequest.push('mocktilleryPluginSetOpts');
    });

    debug('Mocktillery Plugin initialized');
    
  } else {
    console.warn('#############################################################')
    console.warn('## artillery-plugin-mocktillery was loaded but mocktillery ##')
    console.warn('## configuration not found in script configuration         ##')
    console.warn('#############################################################')
  }

  return this;
}
