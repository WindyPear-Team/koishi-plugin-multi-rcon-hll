import { Context, Schema, User, Session, Database } from 'koishi'
import { Socket } from 'net'
import dayjs from 'dayjs';

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
  adminIds?: string[];
  allowedGroups?: string[]; // 新增：允许使用的群组 ID 列表
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
    adminIds: Schema.array(Schema.string()).description('管理员 ID 列表'),
    allowedGroups: Schema.array(Schema.string()).description('允许使用的群组 ID 列表'), // 新增
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

declare module 'koishi' {
  interface Tables {
    vip_data: VipData,
    player_stats: PlayerStats
  }
}

class HLLConnection {
  private socket: Socket
  private xorKey: Buffer | null = null
  private isConnected = false

  constructor() {
    this.socket = new Socket()
    this.socket.setTimeout(20_000) // 20 秒超时
  }

  async connect(host: string, port: number, password: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.connect(port, host, () => {
        // 接收 XOR 密钥
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
      // 发送认证命令
      const authCommand = `login ${password}`
      this.send(authCommand)

      // 接收认证响应
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

        // 检查是否继续接收数据
        if (data.length >= msglen) {
          this.socket.once('data', onData)
        } else {
          resolve(buffer)
        }
      }

      this.socket.once('data', onData)
      this.socket.once('error', reject)
      this.socket.once('timeout', () => resolve(buffer)) // 超时返回已接收数据
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

function parseTime(timeStr: string): Date {
  let totalSeconds = 0;

  const regex = /(\d+)([dmyhs])/g;
  let match;

  while ((match = regex.exec(timeStr)) !== null) {
    const value = parseInt(match[1]);
    const unit = match[2];
    switch (unit) {
      case 's':
        totalSeconds += value;
        break;
      case 'h':
        totalSeconds += value * 60 * 60;
        break;
      case 'd':
        totalSeconds += value * 24 * 60 * 60;
        break;
      case 'm':
        totalSeconds += value * 30 * 24 * 60 * 60;
        break;
      case 'y':
        totalSeconds += value * 365 * 24 * 60 * 60;
        break;
    }
  }

  return dayjs().add(totalSeconds, 'seconds').toDate();
}

const killRegex = /KILL: (.*)\((Allies|Axis)\/(.*)\)\s->\s(.*)\((Allies|Axis)\/(.*)\)\swith\s(.*)/;
const teamKillRegex = /TEAM KILL: (.*)\((Allies|Axis)\/(.*)\)\s->\s(.*)\((Allies|Axis)\/(.*)\)\swith\s(.*)/;

export function apply(ctx: Context, config: Config) {

    ctx.model.extend('vip_data', {
        id: 'unsigned',
        uid: 'string',
        serverId: 'string',
        expireAt: 'timestamp',
        remark: 'string',
    }, {
        primary: 'id',
        autoInc: true,
    });

    ctx.model.extend('player_stats', {
        uid: 'string',
        serverId: 'string',
        playerName: 'string',
        kills: 'integer',
        deaths: 'integer',
        teamKills: 'integer',
        lastUpdate: 'timestamp',
    }, {
        primary: ['uid', 'serverId'],
    });

  const { servers, customCommands } = config

  // 自定义指令映射表
  const commandMap = new Map<string, string>()
  customCommands.forEach(({ alias, command }) => {
    commandMap.set(alias, command)
  })

  servers.forEach((server) => {

            // 注册命令的公共属性
            const baseCommand = ctx.command(server.command)

            baseCommand.usage('需要管理员权限才能使用')

        baseCommand.action(async ({ session }, inputCommand) => {
                  // 群组检查
                  if (server.allowedGroups && !server.allowedGroups.includes(session?.channelId!)) {
                      return '本群组不允许使用此命令。';
                  }
                    if (server.adminIds && !server.adminIds.includes(session?.userId!)) {
                        return '权限不足，只有管理员才能使用此命令。';
                    }
                    const conn = new HLLConnection()
                    try {
                        await conn.connect(server.host, server.port, server.password)

                        // 替换自定义指令
                        const [firstWord, ...rest] = inputCommand.split(' ')
                        const mappedCommand = commandMap.get(firstWord) || firstWord
                        const finalCommand = [mappedCommand, ...rest].join(' ')

                        conn.send(finalCommand)
                        const response = await conn.receive()
                        return `[HLL] ${server.name} 响应：\n${response.toString()}`
                    } catch (error) {
                        return `[HLL] 错误：${error.message}`
                    } finally {
                        conn.close()
                    }
                })

      // 添加 .查服 指令
        if (server.enableGamestateCommand) {
            baseCommand.subcommand('.查服')
              .action(async ({session}) => {
                   // 群组检查
                    if (server.allowedGroups && !server.allowedGroups.includes(session?.channelId!)) {
                        return '本群组不允许使用此命令。';
                    }
                  try {
                      const conn = new HLLConnection()
                      await conn.connect(server.host, server.port, server.password)

                      // 获取服务器名称
                      conn.send('get name')
                      const serverNameResponse = await conn.receive().then(buffer => buffer.toString());
                      const serverName = serverNameResponse.trim(); // 去除可能存在的空格

                      conn.send('get gamestate')
                      const response = await conn.receive().then(buffer => buffer.toString());

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
                      conn.close();
                      return `${serverName} 服务器状态：\n` +
                          `在线玩家: 同盟国: ${players.split('-')[0].replace('Allied:', '').trim()} - 轴心国: ${players.split('-')[1].replace('Axis:', '').trim()}\n` +
                          `比分: 同盟国: ${score.split('-')[0].replace('Allied:', '').trim()} - 轴心国: ${score.split('-')[1].replace('Axis:', '').trim()}\n` +
                          `剩余时间: ${time}\n` +
                          `当前地图: ${map}\n` +
                          `下一张地图: ${nextMap}`;

                  } catch (error) {
                      return `[HLL] 错误：${error.message}`;
                  } finally {
                  }
              }).usage('查询服务器状态')
        }

      // 添加 .群发 指令
      if (server.enableMassMessage) {
                baseCommand.subcommand('.群发 <message:text>')
          .action(async ({ session }, message) => {
                       // 群组检查
                        if (server.allowedGroups && !server.allowedGroups.includes(session?.channelId!)) {
                            return '本群组不允许使用此命令。';
                        }
                      if (server.adminIds && !server.adminIds.includes(session?.userId!)) {
                          return '权限不足，只有管理员才能使用此命令。';
                      }
            const conn = new HLLConnection()
            try {
              await conn.connect(server.host, server.port, server.password)

              // 获取玩家 IDs
              conn.send('Get PlayerIds')
              const playerIdsResponse = await conn.receive().then(buffer => buffer.toString());

              // 使用正则表达式解析玩家 IDs
              const playerLines = playerIdsResponse.split('\n');
              const playerUids: string[] = [];

              playerLines.forEach(line => {
                  line = line.trim();
                  if (line === '') return;

                  // 移除行首编号
                  const lineWithoutNumber = line.replace(/^\d+\s*/, '');

                  // 使用正则表达式匹配 玩家名称 : UID
                  const regex = /(.*?):\s*([a-f0-9]{32}|765611\d{10,})/g; // 匹配32位md5或者steamID64
                  let match;

                  while ((match = regex.exec(lineWithoutNumber)) !== null) {
                      const uid = match[2]; // UID 在第二个捕获组
                      if (uid) {
                          playerUids.push(uid);
                      }
                  }
              });

              // 群发消息
              let successCount = 0;
              for (const uid of playerUids) {
                  const sendMessageCommand = `Message ${uid} ${message}`;
                  conn.send(sendMessageCommand);
                  await conn.receive(); // 可以选择等待响应，也可以不等待 (fire and forget)
                  successCount++;
              }

              return `成功向 ${successCount} 位玩家发送消息。`;

            } catch (error) {
              return `[HLL] 错误：${error.message}`;
            } finally {
                conn.close();
            }
                }).usage('管理员群发消息');
      }

      // 添加 .VIP 指令
      if (server.enableVip) {
          baseCommand.subcommand('.VIP <uid:string> <duration:string> [remark:string]')
              .action(async ({ session }, uid, durationStr, remark = '添加VIP') => {
                   // 群组检查
                   if (server.allowedGroups && !server.allowedGroups.includes(session?.channelId!)) {
                       return '本群组不允许使用此命令。';
                   }
                  if (server.adminIds && !server.adminIds.includes(session?.userId!)) {
                      return '权限不足，只有管理员才能使用此命令。';
                  }

                  const conn = new HLLConnection()
                  try {
                      await conn.connect(server.host, server.port, server.password)

                      // 解析时间
                      const expireAt = parseTime(durationStr);

                      // 添加 VIP
                      conn.send(`VipAdd ${uid} ${remark}`)
                      await conn.receive()

                      // 保存到数据库
                      await ctx.database.create('vip_data', {
                          uid,
                          serverId: server.command,
                          expireAt,
                          remark,
                      })

                      return `已成功为 UID ${uid} 添加 VIP，到期时间：${dayjs(expireAt).format('YYYY-MM-DD HH:mm:ss')}，备注：${remark}。`

                  } catch (error) {
                      return `[HLL] 错误：${error.message}`;
                  } finally {
                      conn.close();
                  }
              }).usage('管理员添加VIP');
      }

       if (server.enableStats) {
          baseCommand.subcommand('.查战绩 <uid:string>')
              .action(async ({ session }, uid) => {
                    // 群组检查
                    if (server.allowedGroups && !server.allowedGroups.includes(session?.channelId!)) {
                        return '本群组不允许使用此命令。';
                    }
                  try {
                      const [stats] = await ctx.database.get('player_stats', { uid, serverId: server.command });
                      if (!stats) {
                          return '未找到该玩家的战绩信息。';
                      }
                      const kdRatio = stats.deaths === 0 ? stats.kills : (stats.kills / stats.deaths).toFixed(2);
                      const lastUpdate = dayjs(stats.lastUpdate).format('YYYY年MM月DD日 HH时mm分');
                      return `玩家 ${stats.playerName} uid${uid}\n` +
                          `击杀总数：${stats.kills}\n` +
                          `死亡总数：${stats.deaths}\n` +
                          `TK总数：${stats.teamKills}\n` +
                          `KD计算：${kdRatio}\n` +
                          `统计至 ${lastUpdate}`;
                  } catch (error) {
                      return `[HLL] 错误：${error.message}`;
                  }
              }).usage('查询玩家战绩');

        baseCommand.subcommand('.清除战绩')
               .action(async ({ session }) => {
                   // 群组检查
                   if (server.allowedGroups && !server.allowedGroups.includes(session?.channelId!)) {
                       return '本群组不允许使用此命令。';
                   }
                    if (server.adminIds && !server.adminIds.includes(session?.userId!)) {
                        return '权限不足，只有管理员才能使用此命令。';
                    }
                    try {
                        await ctx.database.remove('player_stats', { serverId: server.command });
                        return `已成功清除 ${server.name} 服务器的所有战绩数据。`;
                    } catch (error) {
                        return `[HLL] 错误：${error.message}`;
                    }
                }).usage('管理员清除服务器战绩');

            ctx.setInterval(async () => {
                const conn = new HLLConnection();
                try {
                    await conn.connect(server.host, server.port, server.password);

                    // 获取当前所有在线玩家的日志信息
                    const killLog = await getLog(conn, 'showlog 5 kill');
                    const teamKillLog = await getLog(conn, 'showlog 5 team kill');

                    // 处理击杀日志
                    await processKillLog(ctx, server.command, killLog, false);
                    // 处理团队击杀日志
                    await processKillLog(ctx, server.command, teamKillLog, true);

                    ctx.logger.info(`[${server.name}] 战绩统计已更新。`);
                } catch (error) {
                    ctx.logger.error(`[${server.name}] 战绩统计失败：${error.message}`);
                } finally {
                    conn.close();
                }
            }, 300_000);
        }
  })

  // 定时检查 VIP 是否过期
  ctx.setInterval(async () => {
    const now = new Date()
    const expiredVips = await ctx.database.get('vip_data', {
      expireAt: { $lte: now },
    })

    for (const vip of expiredVips) {
      const server = servers.find(s => s.command === vip.serverId)
      if (!server) {
        ctx.logger.warn(`找不到服务器配置：${vip.serverId}`)
        continue
      }

      const conn = new HLLConnection()
      try {
        await conn.connect(server.host, server.port, server.password)

        // 移除 VIP
        conn.send(`VipDel ${vip.uid}`)
        await conn.receive()

        // 从数据库删除
        await ctx.database.remove('vip_data', { uid: vip.uid, serverId: vip.serverId })

        ctx.logger.info(`UID ${vip.uid} 的 VIP 已过期，已从服务器 ${server.name} 移除。`)
      } catch (error) {
        ctx.logger.error(`移除 UID ${vip.uid} 的 VIP 失败：${error.message}`)
      } finally {
        conn.close()
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

    for (const line of lines) {
        let match;
        if (isTeamKill) {
            match = teamKillRegex.exec(line);
        } else {
            match = killRegex.exec(line);
        }

        if (match) {
            const killerName = match[1];
            const killerUid = match[3];
            const victimName = match[4];
            const victimUid = match[6];

            if (!killerUid || !victimUid) {
                continue;
            }
            // 获取现有战绩数据
            const [existingKillerStats] = await ctx.database.get('player_stats', { uid: killerUid, serverId });
            const [existingVictimStats] = await ctx.database.get('player_stats', { uid: victimUid, serverId });

            // 初始化数据 (如果没有找到记录)
            const killerKills = existingKillerStats ? existingKillerStats.kills : 0;
            const killerDeaths = existingKillerStats ? existingKillerStats.deaths : 0;
            const killerTeamKills = existingKillerStats ? existingKillerStats.teamKills : 0;
            const victimKills = existingVictimStats ? existingVictimStats.kills : 0;
            const victimDeaths = existingVictimStats ? existingVictimStats.deaths : 0;
            const victimTeamKills = existingVictimStats ? existingVictimStats.teamKills : 0

            // 更新数据
            const newKillerKills = killerKills+1
            const newKillerTeamKills= isTeamKill ? killerTeamKills+1:killerTeamKills
            const newVictimDeaths= victimDeaths+1
            // 定义 upsert 数据
            const killerUpdate: PlayerStats = {
                uid: killerUid,
                serverId,
                playerName: killerName,
                kills: newKillerKills,
                deaths: killerDeaths,
                teamKills: newKillerTeamKills,
                lastUpdate: new Date()
            };

            const victimUpdate: PlayerStats = {
                uid: victimUid,
                serverId,
                playerName: victimName,
                kills: victimKills,
                deaths: newVictimDeaths,
                teamKills: victimTeamKills,
                lastUpdate: new Date()
            };

                await ctx.database.upsert('player_stats', [killerUpdate, victimUpdate], ['uid', 'serverId']);

        }
    }
}