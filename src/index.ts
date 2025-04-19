import { Context, Schema, Session, Database } from 'koishi'
import { Socket } from 'net'
import dayjs from 'dayjs';
import { v4 as uuidv4 } from 'uuid';

export const name = 'multi-rcon-hll'

export const inject = ['database']

export interface Config {
  servers: ServerConfig[]
  customCommands: CustomCommand[]
}

export interface ServerConfig {
  name: string
  command: string
  host: string
  port: number
  password: string
  enableGamestateCommand?: boolean;
  enableMassMessage?: boolean;
  enableVip?: boolean;
  enableStats?: boolean;
  enableCdKeyRedemption?: boolean;
  adminIds?: string[];
  allowedGroups?: string[];
}

export interface CustomCommand {
  alias: string
  command: string
}

export const Config: Schema<Config> = Schema.object({
  servers: Schema.array(Schema.object({
    name: Schema.string().required().description('服务器名称'),
    command: Schema.string().required().description('指令名（如“hll1”）'),
    host: Schema.string().required().description('服务器地址'),
    port: Schema.number().default(10101).description('HLL RCON 端口（默认 10101）'),
    password: Schema.string().required().description('RCON 密码'),
    enableGamestateCommand: Schema.boolean().default(false).description('启用 .查服 指令'),
    enableMassMessage: Schema.boolean().default(false).description('启用 .群发 指令'),
    enableVip: Schema.boolean().default(false).description('启用 .VIP 指令'),
    enableStats: Schema.boolean().default(false).description('启用战绩统计'),
    enableCdKeyRedemption: Schema.boolean().default(false).description('启用卡密兑换VIP功能'),
    adminIds: Schema.array(Schema.string()).description('管理员 ID 列表'),
    allowedGroups: Schema.array(Schema.string()).description('允许使用的群组 ID 列表'),
  })).description('服务器配置'),
  customCommands: Schema.array(Schema.object({
    alias: Schema.string().required().description('自定义指令别名（如“踢出”）'),
    command: Schema.string().required().description('实际指令（如“kick”）'),
  })).description('自定义指令映射'),
})

export interface VipData {
  id: number
  uid: string
  serverId: string
  expireAt: Date
  remark: string
}

export interface PlayerStats {
  uid: string;
  serverId: string;
  playerName: string;
  kills: number;
  deaths: number;
  teamKills: number;
  lastUpdate: Date;
}

export interface GlobalCdKey {
    id: number;
    key: string;
    duration: string;
    remark: string;
    isUsed: boolean;
    usedByUid?: string;
    usedAt?: Date;
    createdAt: Date;
}

export interface ServerCdKey {
    id: number;
    key: string;
    serverId: string;
    duration: string;
    remark: string;
    isUsed: boolean;
    usedByUid?: string;
    usedAt?: Date;
    createdAt: Date;
}

declare module 'koishi' {
  interface Tables {
    vip_data: VipData,
    player_stats: PlayerStats,
    global_cdkeys: GlobalCdKey,
    server_cdkeys: ServerCdKey,
  }
}

class HLLConnection {
  private socket: Socket
  private xorKey: Buffer | null = null
  private isConnected = false

  constructor() {
    this.socket = new Socket()
    this.socket.setTimeout(20_000)
  }

  async connect(host: string, port: number, password: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.connect(port, host, () => {
        this.socket.once('data', (keyData) => {
          this.xorKey = keyData
          this._authenticate(password)
            .then(resolve)
            .catch(reject)
        })
      })
      this.socket.on('error', (err) => reject(err))
      this.socket.on('timeout', () => reject(new Error('连接超时')))
    })
  }

  private async _authenticate(password: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const authCommand = `login ${password}`
      this.send(authCommand)
      this.receive()
        .then((response) => {
          if (response.toString().trim() !== 'SUCCESS') {
            throw new Error('HLL 认证失败：密码错误')
          }
          this.isConnected = true
          resolve()
        })
        .catch(reject)
    })
  }

  send(command: string): void {
    if (!this.xorKey) {
      throw new Error('XOR 密钥未初始化')
    }
    const encoded = this._xor(Buffer.from(command))
    this.socket.write(encoded)
  }

  async receive(): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0)
      const msglen = 32_768
      const onData = (data: Buffer) => {
        const decoded = this._xor(data)
        buffer = Buffer.concat([buffer, decoded])
        if (data.length >= msglen) {
          this.socket.once('data', onData)
        } else {
          resolve(buffer)
        }
      }
      this.socket.once('data', onData)
      this.socket.once('error', reject)
      this.socket.once('timeout', () => resolve(buffer))
    })
  }

  private _xor(data: Buffer): Buffer {
    if (!this.xorKey) {
      throw new Error('XOR 密钥未初始化')
    }
    const result = Buffer.alloc(data.length)
    for (let i = 0; i < data.length; i++) {
      result[i] = data[i] ^ this.xorKey[i % this.xorKey.length]
    }
    return result
  }

  close() {
    this.socket.destroy()
    this.isConnected = false
  }
}

function parseTime(timeStr: string): Date | null {
  let totalSeconds = 0;
  let matched = false;
  const regex = /(\d+)([dmyhs])/g;
  let match;
  while ((match = regex.exec(timeStr)) !== null) {
    matched = true;
    const value = parseInt(match[1]);
    if (isNaN(value) || value <= 0) return null;
    const unit = match[2];
    switch (unit) {
      case 's': totalSeconds += value; break;
      case 'h': totalSeconds += value * 3600; break;
      case 'd': totalSeconds += value * 86400; break;
      case 'm': totalSeconds += value * 2592000; break; // 30 days
      case 'y': totalSeconds += value * 31536000; break; // 365 days
      default: return null;
    }
  }
  if (!matched) return null;
  const futureDate = dayjs().add(totalSeconds, 'seconds');
  if (futureDate.isBefore(dayjs())) return null;
  return futureDate.toDate();
}

const killRegex = /KILL: (.*)\((Allies|Axis)\/(.*?)\)\s*->\s*(.*)\((Allies|Axis)\/(.*?)\)\s*with\s*(.*)/;
const teamKillRegex = /TEAM KILL: (.*)\((Allies|Axis)\/(.*?)\)\s*->\s*(.*)\((Allies|Axis)\/(.*?)\)\s*with\s*(.*)/;

export function apply(ctx: Context, config: Config) {

    ctx.model.extend('vip_data', {
        id: 'unsigned', uid: 'string', serverId: 'string',
        expireAt: 'timestamp', remark: 'string',
    }, { primary: 'id', autoInc: true });

    ctx.model.extend('player_stats', {
        uid: 'string', serverId: 'string', playerName: 'string',
        kills: 'integer', deaths: 'integer', teamKills: 'integer',
        lastUpdate: 'timestamp',
    }, { primary: ['uid', 'serverId'] });

    ctx.model.extend('global_cdkeys', {
        id: 'unsigned', key: { type: 'string' }, duration: 'string',
        remark: 'string', isUsed: 'boolean', usedByUid: 'string',
        usedAt: 'timestamp', createdAt: 'timestamp',
    }, { primary: 'id', autoInc: true, unique: ['id'], });

    ctx.model.extend('server_cdkeys', {
        id: 'unsigned', key: 'string', serverId: 'string', duration: 'string',
        remark: 'string', isUsed: 'boolean', usedByUid: 'string',
        usedAt: 'timestamp', createdAt: 'timestamp',
    }, { primary: 'id', autoInc: true });

  const { servers, customCommands } = config

  const commandMap = new Map<string, string>()
  customCommands.forEach(({ alias, command }) => {
    commandMap.set(alias, command)
  })

  servers.forEach((server) => {

    const baseCommand = ctx.command(server.command)
      .usage(`(${server.name}) 相关指令`);

    baseCommand.action(async ({ session }, inputCommand) => {
      if (!inputCommand) return '请输入指令';
      if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此服务器的命令。';
      if (!server.adminIds?.includes(session?.userId!)) return '权限不足，只有管理员才能使用此命令。';

      const conn = new HLLConnection()
      try {
        await conn.connect(server.host, server.port, server.password)
        const [firstWord, ...rest] = inputCommand.split(' ')
        const mappedCommand = commandMap.get(firstWord) || firstWord
        const finalCommand = [mappedCommand, ...rest].join(' ')
        conn.send(finalCommand)
        const response = await conn.receive()
        return `[HLL] ${server.name} 响应：\n${response.toString()}`
      } catch (error) {
        return `[HLL] 错误 (${server.name})：${error.message}`
      } finally {
        conn.close()
      }
    })
    .usage('执行原始 RCON 指令 (管理员)')

    if (server.enableGamestateCommand) {
        baseCommand.subcommand('.查服')
          .action(async ({session}) => {
              if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
              let conn: HLLConnection | null = null;
              try {
                  conn = new HLLConnection()
                  await conn.connect(server.host, server.port, server.password)
                  conn.send('get name')
                  const serverName = (await conn.receive()).toString().trim();
                  conn.send('get gamestate')
                  const response = (await conn.receive()).toString();
                  const lines = response.split('\n');
                  const playersLine = lines.find(line => line.startsWith('Players:'));
                  const scoreLine = lines.find(line => line.startsWith('Score:'));
                  const timeLine = lines.find(line => line.startsWith('Remaining Time:'));
                  const mapLine = lines.find(line => line.startsWith('Map:'));
                  const nextMapLine = lines.find(line => line.startsWith('Next Map:'));
                  const players = playersLine ? playersLine.substring(playersLine.indexOf(':') + 1).trim() : '未知';
                  const score = scoreLine ? scoreLine.substring(scoreLine.indexOf(':') + 1).trim() : '未知';
                  const time = timeLine ? timeLine.substring(timeLine.indexOf(':') + 1).trim() : '未知';
                  const map = mapLine ? mapLine.substring(mapLine.indexOf(':') + 1).trim() : '未知';
                  const nextMap = nextMapLine ? nextMapLine.substring(nextMapLine.indexOf(':') + 1).trim() : '未知';
                  const alliedPlayers = players.split('-')[0]?.replace('Allied:', '').trim() || '?';
                  const axisPlayers = players.split('-')[1]?.replace('Axis:', '').trim() || '?';
                  const alliedScore = score.split('-')[0]?.replace('Allied:', '').trim() || '?';
                  const axisScore = score.split('-')[1]?.replace('Axis:', '').trim() || '?';
                  return `${serverName} 服务器状态：\n` +
                         `在线玩家: 同盟国: ${alliedPlayers} - 轴心国: ${axisPlayers}\n` +
                         `比分: 同盟国: ${alliedScore} - 轴心国: ${axisScore}\n` +
                         `剩余时间: ${time}\n` +
                         `当前地图: ${map}\n` +
                         `下一张地图: ${nextMap}`;
              } catch (error) {
                  return `[HLL] 错误 (${server.name})：${error.message}`;
              } finally {
                   if(conn) conn.close();
              }
          }).usage('查询服务器状态')
    }

    if (server.enableMassMessage) {
        baseCommand.subcommand('.群发 <message:text>')
            .action(async ({ session }, message) => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                if (!server.adminIds?.includes(session?.userId!)) return '权限不足，只有管理员才能使用此命令。';
                let conn: HLLConnection | null = null;
                try {
                    conn = new HLLConnection();
                    await conn.connect(server.host, server.port, server.password)
                    conn.send('Get PlayerIds')
                    const playerIdsResponse = (await conn.receive()).toString();
                    const playerLines = playerIdsResponse.split('\n');
                    const playerUids: string[] = [];
                    playerLines.forEach(line => {
                        line = line.trim();
                        if (line === '') return;
                        const lineWithoutNumber = line.replace(/^\d+\s*/, '');
                        const regex = /(.*?):\s*([a-f0-9]{32}|765611\d{10,})/g;
                        let match;
                        while ((match = regex.exec(lineWithoutNumber)) !== null) { if (match[2]) playerUids.push(match[2]); }
                    });
                    let successCount = 0;
                    for (const uid of playerUids) {
                        const sendMessageCommand = `Message ${uid} ${message}`;
                        conn.send(sendMessageCommand);
                       await new Promise(resolve => setTimeout(resolve, 50));
                        await conn.receive();
                        successCount++;
                    }
                    return `成功向 ${successCount} 位玩家发送消息(${server.name})。`;
                } catch (error) {
                    return `[HLL] 错误 (${server.name})：${error.message}`;
                } finally {
                    if(conn) conn.close();
                }
            }).usage('管理员群发消息');
    }

    if (server.enableVip) {
        baseCommand.subcommand('.VIP <uid:string> <duration:string> [remark:string]')
            .action(async ({ session }, uid, durationStr, remark = '添加VIP') => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                if (!server.adminIds?.includes(session?.userId!)) return '权限不足，只有管理员才能使用此命令。';
                let conn: HLLConnection | null = null;
                try {
                    conn = new HLLConnection();
                    const expireAt = parseTime(durationStr);
                    if (!expireAt) return '无效的时间格式或时间已过期。请使用例如 1d, 30m, 1y, 5h30m 等格式。';

                    await conn.connect(server.host, server.port, server.password);
                    conn.send(`VipAdd ${uid} "${remark}"`)
                    await conn.receive()
                    await ctx.database.create('vip_data', { uid, serverId: server.command, expireAt, remark })
                    return `已成功为 UID ${uid} 添加 VIP (${server.name})，到期时间：${dayjs(expireAt).format('YYYY-MM-DD HH:mm:ss')}，备注：${remark}。`
                } catch (error) {
                    return `[HLL] 错误 (${server.name})：${error.message}`;
                } finally {
                    if(conn) conn.close();
                }
            }).usage('管理员添加VIP (格式: .VIP <UID> <时间 如 1d/30m/1y/5h30m> [备注])');
     }

    if (server.enableStats) {
      baseCommand.subcommand('.查战绩 <uid:string>')
          .action(async ({ session }, uid) => {
              if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
              try {
                  const [stats] = await ctx.database.get('player_stats', { uid, serverId: server.command });
                  if (!stats) return `未找到玩家 UID ${uid} 在服务器 ${server.name} 的战绩信息。`;
                  const kdRatio = stats.deaths === 0 ? stats.kills.toFixed(2) : (stats.kills / stats.deaths).toFixed(2);
                  const lastUpdate = dayjs(stats.lastUpdate).format('YYYY年MM月DD日 HH:mm:ss');
                  return `玩家 ${stats.playerName} (UID: ${uid}) 在 ${server.name} 的战绩：\n` +
                         `击杀总数：${stats.kills}\n` +
                         `死亡总数：${stats.deaths}\n` +
                         `TK总数：${stats.teamKills}\n` +
                         `KD计算：${kdRatio}\n` +
                         `统计至 ${lastUpdate}`;
              } catch (error) {
                  return `[HLL] 错误 (${server.name})：${error.message}`;
              }
          }).usage('查询玩家战绩');

      baseCommand.subcommand('.清除战绩')
           .action(async ({ session }) => {
               if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
               if (!server.adminIds?.includes(session?.userId!)) return '权限不足，只有管理员才能使用此命令。';
                try {
                    const result = await ctx.database.remove('player_stats', { serverId: server.command });
                    return `已成功清除 ${server.name} (${server.command}) 服务器 ${result.removed} 条战绩数据。`;
                } catch (error) {
                    return `[HLL] 错误 (${server.name})：${error.message}`;
                }
            }).usage('管理员清除本服务器所有战绩');

        ctx.setInterval(async () => {
            if (!server.enableStats) return;
            let conn: HLLConnection | null = null;
            try {
                conn = new HLLConnection();
                await conn.connect(server.host, server.port, server.password);
                const killLog = await getLog(conn, 'showlog 5 kill');
                const teamKillLog = await getLog(conn, 'showlog 5 team kill');
                await processKillLog(ctx, server.command, killLog, false);
                await processKillLog(ctx, server.command, teamKillLog, true);
                ctx.logger.info(`[${server.name}] 战绩统计已更新。`);
            } catch (error) {
                 ctx.logger.error(`[${server.name}] 战绩统计失败：${error.message}`);
            } finally {
                if (conn) conn.close();
            }
        }, 300_000);
    }

    if (server.enableCdKeyRedemption) {
        baseCommand.subcommand('.生成卡密 <type:string> <duration:string> <count:integer> [remark:string]')
            .action(async ({ session }, type, durationStr, count, remark = 'VIP卡密') => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                if (!server.adminIds?.includes(session?.userId!)) return '权限不足，只有管理员才能生成卡密。';
                if (!['global', 'server'].includes(type)) return '无效的卡密类型，请指定 "global" 或 "server"。';
                const durationCheck = parseTime(durationStr);
                if (!durationCheck) return '无效的时间格式或时间已过期。请使用例如 1d, 30m, 1y, 5h30m 等格式。';
                if (!Number.isInteger(count) || count <= 0) return '生成的数量必须是一个正整数。';
                if (count > 100) return '出于性能考虑，单次最多生成 100 个卡密。';

                const keysToCreate: (Omit<GlobalCdKey, 'id'> | Omit<ServerCdKey, 'id'>)[] = [];
                const generatedKeys: string[] = [];
                const now = new Date();

                for (let i = 0; i < count; i++) {
                     const newKey = uuidv4();
                     generatedKeys.push(newKey);
                     const commonData = { key: newKey, duration: durationStr, remark, isUsed: false, createdAt: now };
                     if (type === 'global') {
                        keysToCreate.push({ ...commonData });
                    } else {
                        keysToCreate.push({ ...commonData, serverId: server.command });
                     }
                }

                try {
                    const tableName = type === 'global' ? 'global_cdkeys' : 'server_cdkeys';
                    await ctx.database.create(tableName, keysToCreate as any); // 使用 any 避免类型体操
                    return `成功生成 ${count} 个 ${type === 'global' ? '全局' : `服务器 ${server.name} (${server.command}) 专用`} 卡密 (时长: ${durationStr}, 备注: ${remark})：\n` + generatedKeys.join('\n');
                } catch (error) {
                    if (error.message.includes('UNIQUE constraint failed')) {
                        return `[HLL] 错误 (${server.name})：生成卡密时遇到重复，请重试。`;
                    }
                    return `[HLL] 错误 (${server.name})：批量生成卡密时发生数据库错误: ${error.message}`;
                }
            }).usage('管理员批量生成卡密 (格式: .生成卡密 <global|server> <时间> <数量> [备注])');

        baseCommand.subcommand('.卡密兑换 <uid:string> <key:string>')
            .action(async ({ session }, uid, key) => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                 if (!server.enableVip) return '本服务器未启用VIP功能，无法兑换卡密。';

                let cdKeyRecord: GlobalCdKey | ServerCdKey | null = null;
                let keyType: 'global' | 'server' = 'server';
                let durationStr: string = '';
                let remark: string = '';
                let isGlobalKeyUsedOnThisServer = false;

                try {
                    const [serverKey] = await ctx.database.get('server_cdkeys', { key, serverId: server.command });
                    if (serverKey) {
                        if (serverKey.isUsed) return '此服务器卡密已被使用。';
                        cdKeyRecord = serverKey; keyType = 'server'; durationStr = serverKey.duration; remark = serverKey.remark;
                    } else {
                        const [globalKey] = await ctx.database.get('global_cdkeys', { key });
                        if (globalKey) {
                            if (globalKey.isUsed) return '此全局卡密已被使用。';
                            const existingVip = await ctx.database.get('vip_data', {
                                uid: uid, serverId: server.command
                            });
                            if(existingVip.length > 0) isGlobalKeyUsedOnThisServer = true;
                            cdKeyRecord = globalKey; keyType = 'global'; durationStr = globalKey.duration; remark = globalKey.remark;
                        }
                    }

                    if (!cdKeyRecord) return '无效的卡密。';
                    const expireAt = parseTime(durationStr);
                    if (!expireAt) return '卡密关联的时间格式无效。';
                    if (keyType === 'global' && isGlobalKeyUsedOnThisServer) return `您已使用全局卡密 ${key} 在服务器 ${server.name} 兑换过 VIP。`;

                    let conn: HLLConnection | null = null;
                    try {
                        conn = new HLLConnection();
                        await conn.connect(server.host, server.port, server.password);
                        const finalRemark = `${remark} (卡密: ${key})`;
                        conn.send(`VipAdd ${uid} "${finalRemark}"`);
                        await conn.receive();
                       await ctx.database.create('vip_data', { uid, serverId: server.command, expireAt, remark: finalRemark });

                        const now = new Date();
                        const updateData = { isUsed: true, usedByUid: uid, usedAt: now };
                        if (keyType === 'global') {
                            await ctx.database.set('global_cdkeys', { key: cdKeyRecord.key }, updateData);
                        } else {
                            await ctx.database.set('server_cdkeys', { id: cdKeyRecord.id }, updateData);
                        }
                        return `卡密 ${key} 兑换成功！已为 UID ${uid} 添加 ${durationStr} VIP (${server.name})，备注：${remark}。`;
                    } catch (rconError) {
                         ctx.logger.error(`[HLL] RCON 操作失败 (${server.name}) 卡密 ${key} for ${uid}: ${rconError.message}`);
                         return `[HLL] 错误 (${server.name})：VIP 添加失败，请联系管理员。错误: ${rconError.message}`;
                    } finally {
                        if(conn) conn.close();
                    }
                } catch (dbError) {
                    ctx.logger.error(`[HLL] 卡密兑换数据库操作失败 (${server.name}) Key ${key}: ${dbError.message}`);
                    return `[HLL] 错误 (${server.name})：兑换过程中发生数据库错误，请稍后重试。`;
                }
            }).usage('使用卡密兑换VIP (格式: .卡密兑换 <游戏内UID> <卡密>)');
    }

  })

  ctx.setInterval(async () => {
    const now = new Date()
    const expiredVips = await ctx.database.get('vip_data', { expireAt: { $lte: now } })
    if (!expiredVips.length) return;

    for (const vip of expiredVips) {
      const server = servers.find(s => s.command === vip.serverId)
      if (!server) {
        ctx.logger.warn(`处理过期VIP时找不到服务器配置：${vip.serverId}, UID: ${vip.uid}`)
        // 从数据库中删除这条无效关联的VIP记录，防止重复处理
        await ctx.database.remove('vip_data', { id: vip.id });
        continue
      }

      let conn: HLLConnection | null = null;
      try {
         conn = new HLLConnection();
        await conn.connect(server.host, server.port, server.password)
        conn.send(`VipDel ${vip.uid}`)
        await conn.receive()
        await ctx.database.remove('vip_data', { id: vip.id })
        ctx.logger.info(`UID ${vip.uid} 的 VIP 已过期，已从服务器 ${server.name} 移除。`)
      } catch (error) {
        ctx.logger.error(`移除 UID ${vip.uid} (${server.name}) 的过期 VIP 失败：${error.message}`)
        // 可以考虑添加重试逻辑或标记，避免因临时错误导致VIP未移除
      } finally {
         if(conn) conn.close()
      }
    }
  }, 3600_000)
}

async function getLog(conn: HLLConnection, command: string): Promise<string> {
  conn.send(command);
  const response = await conn.receive();
  return response.toString();
}

async function processKillLog(ctx: Context, serverId: string, log: string, isTeamKill: boolean): Promise<void> {
    const lines = log.split('\n');
    const uidsInLog = new Set<string>();
    const parsedEvents: { killerUid: string, killerName: string, victimUid: string, victimName: string, isTk: boolean }[] = [];

    // 1. 解析日志，收集UID和事件
    for (const line of lines) {
        const match = isTeamKill ? teamKillRegex.exec(line) : killRegex.exec(line);
        if(match){
             const killerUid = match[3];
             const victimUid = match[6];
             if(killerUid) uidsInLog.add(killerUid);
             if(victimUid) uidsInLog.add(victimUid);
             if(killerUid && victimUid){ // 确保双方UID都有效才记录事件
                 parsedEvents.push({
                     killerUid, killerName: match[1].trim(),
                     victimUid, victimName: match[4].trim(),
                     isTk: isTeamKill
                 });
             }
        }
    }

    if (!parsedEvents.length) return; // 没有有效事件，直接返回

    // 2. 预读取所有涉及玩家的现有数据
    const playerCache = new Map<string, PlayerStats>();
    if (uidsInLog.size > 0) {
        const existingPlayers = await ctx.database.get('player_stats', { uid: { $in: Array.from(uidsInLog) }, serverId });
        existingPlayers.forEach(p => playerCache.set(p.uid, p));
    }

    // 3. 聚合更新
    const statsToUpdate = new Map<string, PlayerStats>();
    const now = new Date();

    for (const event of parsedEvents) {
        // 处理击杀者
        let killerStats = statsToUpdate.get(event.killerUid);
        if (!killerStats) {
            const existing = playerCache.get(event.killerUid);
            killerStats = existing ? { ...existing } : { // 复制现有对象或创建新对象
                uid: event.killerUid, serverId, playerName: event.killerName,
                kills: 0, deaths: 0, teamKills: 0, lastUpdate: now
            };
             if (!existing) playerCache.set(event.killerUid, killerStats); // 如果是新玩家，加入缓存
        }
        killerStats.playerName = event.killerName; // 更新为最新的名字
        killerStats.kills += 1;
        if (event.isTk) {
            killerStats.teamKills += 1;
        }
        killerStats.lastUpdate = now;
        statsToUpdate.set(event.killerUid, killerStats);

        // 处理受害者
        let victimStats = statsToUpdate.get(event.victimUid);
        if (!victimStats) {
            const existing = playerCache.get(event.victimUid);
             victimStats = existing ? { ...existing } : {
                uid: event.victimUid, serverId, playerName: event.victimName,
                kills: 0, deaths: 0, teamKills: 0, lastUpdate: now
             };
            if (!existing) playerCache.set(event.victimUid, victimStats);
        }
        victimStats.playerName = event.victimName; // 更新名字
        victimStats.deaths += 1;
        victimStats.lastUpdate = now;
        statsToUpdate.set(event.victimUid, victimStats);
    }

    // 4. 批量 Upsert 更新
    if (statsToUpdate.size > 0) {
        try {
            await ctx.database.upsert('player_stats', Array.from(statsToUpdate.values()));
        } catch (dbError) {
            ctx.logger.error(`[HLL] 批量更新战绩数据库失败 (${serverId}): ${dbError.message}`);
        }
    }
}