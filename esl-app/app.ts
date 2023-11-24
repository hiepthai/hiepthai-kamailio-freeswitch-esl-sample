import Fastify from 'fastify';
import * as crypto from 'crypto';
import dotenv from 'dotenv';
import winston from 'winston';
import { FreeSwitchServer } from 'esl';

const config = dotenv.config().parsed;

const fastify = Fastify({ logger: true });

const logger = winston.createLogger({
  level: config?.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.simple(), winston.format.colorize()),
  defaultMeta: { service: 'esl' },
  transports: [new winston.transports.Console()]
});

// SIP users
const users = {
  1000: { password: 'password1000' },
  1001: { password: 'password1001' }
};

type AuthData = {
  authHeader: string;
};

type ParsedAuthorizationHeader = {
  username: string;
  realm: string;
  nonce: string;
  uri: string;
  response: string;
  nc: string;
  cnonce: string;
  qop: string;
};

function parseAuthorizationHeader(header: string): ParsedAuthorizationHeader {
  header = header.substring(header.indexOf(' ') + 1);
  const credentials = header.split(',');
  const result = {};
  credentials.forEach(credential => {
    const [key, value] = credential.split('=');
    if (key && value) {
      result[key.trim()] = value.replace(/"/g, '');
    }
  });
  return <ParsedAuthorizationHeader>result;
}

function checkCredentials(parsedAuthHeader: ParsedAuthorizationHeader, method: string, uri: string, password: string) {
  const { username, realm, nonce, nc, cnonce, qop } = parsedAuthHeader;

  // create HA1
  const ha1 = crypto.createHash('md5').update(`${username}:${realm}:${password}`).digest('hex');

  // create HA2
  const ha2 = crypto.createHash('md5').update(`${method}:${uri}`).digest('hex');

  // Generate the response
  const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`).digest('hex');

  // Check if the computed response equals the one provided by client
  return response === parsedAuthHeader.response;
}

fastify.post('/auth', async (request, reply) => {
  try {
    const { authHeader } = request.body as AuthData;
    const parsedAuthHeader = parseAuthorizationHeader(authHeader);
    console.log(`Authenticating user ${parsedAuthHeader.username} by ${authHeader}`);

    if (checkCredentials(parsedAuthHeader, 'REGISTER', 'sip:localhost', users[parsedAuthHeader.username].password)) {
      reply.code(200).send({ success: true, message: 'Authentication successful' });
    } else {
      reply.code(403).send({ success: false, message: 'Authentication failed' });
    }
  } catch (err: any) {
    reply.code(400).send({ success: false, message: 'Bad request.' });
  }
});

const start = async () => {
  try {
    await fastify.listen({ host: '0.0.0.0', port: 80 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start().then(() => console.log('Server started!'));

(async () => {
  const fsConnectionOptions = {
    all_events: false,
    my_events: true
  };

  const fsBindingOptions = {
    host: config?.ESL_HOST || 'localhost',
    port: Number(config?.ESL_PORT) || 7000
  };

  const kamailioHost = config?.KAMAILIO_HOST || 'localhost';
  const freeswitchHost = config?.FREESWITCH_HOST || 'localhost';
  const kamailioPort = Number(config?.KAMAILIO_PORT) || 5060;

  const fsServer = new FreeSwitchServer(fsConnectionOptions);
  await fsServer.listen(fsBindingOptions);

  fsServer.on('error', err => {
    logger.error(`Error from FreeSwitch: ${err}`);
  });

  fsServer.on('drop', dropData => {
    logger.debug(`Drop from FreeSwitch from ${dropData.remoteFamily}/${dropData.remoteAddress}:${dropData.remotePort}`);
  });

  fsServer.on('connection', async (call, data) => {
    logger.debug(`Connection from FreeSwitch with UUID ${call.uuid()}`);
    const callee = data.body['variable_sip_to_user'];

    if (callee) {
      const source = data.body['Channel-Channel-Name'];
      const destination = `sofia/${freeswitchHost}/${callee}@${kamailioHost}:${kamailioPort}`;
      logger.debug(`Bridging ${source} to ${destination}`);
      await call.execute('bridge', destination);
    }
  });
})();
