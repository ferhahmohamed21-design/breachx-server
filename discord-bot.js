const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder } = require('discord.js');
const crypto = require('crypto');

let turso = null;

function setTurso(client) {
    turso = client;
}

function generateKeyCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

function isValidKey(key) {
    return /^BreachX-Safe-OB54-[A-Z0-9]{4}-$/.test(key);
}

const GOLD = 0xFFD700;
const RED = 0xFF4444;
const GREEN = 0x44FF66;
const GRAY = 0x888888;

function createEmbed(title, description, color) {
    return new EmbedBuilder()
        .setTitle(title)
        .setDescription(description)
        .setColor(color)
        .setTimestamp();
}

async function deployCommands(clientId, token, guildId) {
    const commands = [
        new SlashCommandBuilder()
            .setName('generate')
            .setDescription('Generate new Breach X keys')
            .addIntegerOption(opt => opt.setName('count').setDescription('Number of keys (1-100)').setRequired(true).setMinValue(1).setMaxValue(100))
            .addStringOption(opt => opt.setName('mode').setDescription('Lock mode').addChoices({ name: 'One Device (HWID)', value: 'hwid' }, { name: 'All Devices', value: 'all' }).setRequired(false))
            .addStringOption(opt => opt.setName('expire').setDescription('Expiry: e.g. 7d, 24h, 30m, 60s').setRequired(false))
            .addStringOption(opt => opt.setName('group').setDescription('Group name (e.g. Premium, Free)').setRequired(false)),

        new SlashCommandBuilder()
            .setName('keycheck')
            .setDescription('Check status of a Breach X key')
            .addStringOption(opt => opt.setName('key').setDescription('The key to check').setRequired(true)),

        new SlashCommandBuilder()
            .setName('stats')
            .setDescription('Show key statistics'),

        new SlashCommandBuilder()
            .setName('revoke')
            .setDescription('Revoke a used key (reset it)')
            .addStringOption(opt => opt.setName('key').setDescription('The key to revoke').setRequired(true)),

        new SlashCommandBuilder()
            .setName('delete')
            .setDescription('Delete a key permanently')
            .addStringOption(opt => opt.setName('key').setDescription('The key to delete').setRequired(true)),

        new SlashCommandBuilder()
            .setName('search')
            .setDescription('Search keys by group or status')
            .addStringOption(opt => opt.setName('query').setDescription('Search: group name, "used", "free", "hwid", "all"').setRequired(true)),
    ];

    const rest = new REST({ version: '10' }).setToken(token);
    try {
        console.log('[BOT] Deploying slash commands...');
        if (guildId) {
            await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body: commands.map(c => c.toJSON()) });
        } else {
            await rest.put(Routes.applicationCommands(clientId), { body: commands.map(c => c.toJSON()) });
        }
        console.log('[BOT] Slash commands deployed!');
    } catch (err) {
        console.error('[BOT] Failed to deploy commands:', err.message);
    }
}

function startBot() {
    const TOKEN = process.env.DISCORD_TOKEN;
    const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
    const GUILD_ID = process.env.DISCORD_GUILD_ID || '';

    if (!TOKEN || !CLIENT_ID) {
        console.log('[BOT] DISCORD_TOKEN or DISCORD_CLIENT_ID not set — bot disabled');
        return;
    }

    const client = new Client({
        intents: [GatewayIntentBits.Guilds]
    });

    client.once('ready', async () => {
        console.log('[BOT] Logged in as ' + client.user.tag);
        await deployCommands(CLIENT_ID, TOKEN, GUILD_ID);
    });

    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isChatInputCommand()) return;
        if (!turso) {
            await interaction.reply({ embeds: [createEmbed('Error', 'Database not connected', RED)], ephemeral: true });
            return;
        }

        const { commandName } = interaction;

        try {
            if (commandName === 'generate') {
                await handleGenerate(interaction);
            } else if (commandName === 'keycheck') {
                await handleKeyCheck(interaction);
            } else if (commandName === 'stats') {
                await handleStats(interaction);
            } else if (commandName === 'revoke') {
                await handleRevoke(interaction);
            } else if (commandName === 'delete') {
                await handleDelete(interaction);
            } else if (commandName === 'search') {
                await handleSearch(interaction);
            }
        } catch (err) {
            console.error('[BOT] Error:', err.message);
            const reply = { embeds: [createEmbed('Error', 'Something went wrong: ' + err.message, RED)], ephemeral: true };
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp(reply);
            } else {
                await interaction.reply(reply);
            }
        }
    });

    client.login(TOKEN).catch(err => {
        console.error('[BOT] Login failed:', err.message);
    });

    return client;
}

async function handleGenerate(interaction) {
    await interaction.deferReply();

    const count = interaction.options.getInteger('count');
    const mode = interaction.options.getString('mode') || 'hwid';
    const expireStr = interaction.options.getString('expire') || '';
    const group = interaction.options.getString('group') || '';
    const locked = mode === 'hwid' ? 1 : 0;

    let expireAt = '';
    if (expireStr) {
        const totalMs = parseExpireString(expireStr);
        if (totalMs <= 0) {
            await interaction.editReply({ embeds: [createEmbed('Error', 'Invalid expire format. Use: `7d`, `24h`, `30m`, `60s`', RED)] });
            return;
        }
        expireAt = new Date(Date.now() + totalMs).toISOString();
    }

    const allCodes = [];
    for (let i = 0; i < count; i++) {
        allCodes.push('BreachX-Safe-OB54-' + generateKeyCode() + '-');
    }

    const stmts = allCodes.map(code => ({
        sql: 'INSERT OR IGNORE INTO keys (key_code, hwid, locked, expire_at, group_name) VALUES (?, ?, ?, ?, ?)',
        args: [code, '', locked, expireAt, group]
    }));
    await turso.batch(stmts);

    const result = await turso.execute({
        sql: 'SELECT key_code FROM keys WHERE key_code IN (' + allCodes.map(() => '?').join(',') + ')',
        args: allCodes
    });
    const keys = result.rows.map(r => r.key_code);

    const modeText = locked ? 'HWID Locked (One Device)' : 'All Devices';
    const expireText = expireStr || 'No limit';
    const groupText = group || 'None';

    const embed = createEmbed(
        'Keys Generated',
        `**${keys.length}** keys created successfully`,
        GOLD
    );
    embed.addFields(
        { name: 'Mode', value: modeText, inline: true },
        { name: 'Expiry', value: expireText, inline: true },
        { name: 'Group', value: groupText, inline: true }
    );

    const keyList = keys.map(k => '`' + k + '`').join('\n');
    if (keyList.length > 1024) {
        embed.addFields({ name: 'Keys', value: 'Too many keys to display. Use `/search` to find them.' });
    } else {
        embed.addFields({ name: 'Keys', value: keyList });
    }

    await interaction.editReply({ embeds: [embed] });
}

async function handleKeyCheck(interaction) {
    await interaction.deferReply();

    const key = interaction.options.getString('key').trim().toUpperCase();

    const result = await turso.execute({ sql: 'SELECT * FROM keys WHERE key_code = ?', args: [key] });
    if (result.rows.length === 0) {
        await interaction.editReply({ embeds: [createEmbed('Key Not Found', 'No key found with code: `' + key + '`', RED)] });
        return;
    }

    const row = result.rows[0];
    const isExpired = row.expire_at && new Date(row.expire_at).getTime() < Date.now();
    const status = isExpired ? 'Expired' : (row.is_used ? 'Used' : 'Free');
    const statusColor = isExpired ? RED : (row.is_used ? GRAY : GREEN);

    const embed = createEmbed('Key Info', 'Details for `' + key + '`', statusColor);
    embed.addFields(
        { name: 'Status', value: status, inline: true },
        { name: 'Mode', value: row.locked ? 'HWID Locked' : 'All Devices', inline: true },
        { name: 'Group', value: row.group_name || 'None', inline: true }
    );

    if (row.hwid) embed.addFields({ name: 'HWID', value: '`' + row.hwid + '`', inline: false });
    if (row.used_at) embed.addFields({ name: 'Used At', value: row.used_at, inline: true });
    if (row.expire_at) embed.addFields({ name: 'Expires', value: isExpired ? 'Expired' : row.expire_at, inline: true });
    embed.addFields({ name: 'Created', value: row.created_at || 'Unknown', inline: true });

    await interaction.editReply({ embeds: [embed] });
}

async function handleStats(interaction) {
    await interaction.deferReply();

    const total = await turso.execute('SELECT COUNT(*) as c FROM keys');
    const used = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE is_used = 1');
    const locked = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE locked = 1');
    const unlocked = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE locked = 0');

    const t = total.rows[0]?.c || 0;
    const u = used.rows[0]?.c || 0;
    const l = locked.rows[0]?.c || 0;
    const a = unlocked.rows[0]?.c || 0;

    const embed = createEmbed('Key Statistics', 'Current database overview', GOLD);
    embed.addFields(
        { name: 'Total Keys', value: '`' + t + '`', inline: true },
        { name: 'Used', value: '`' + u + '`', inline: true },
        { name: 'Free', value: '`' + (t - u) + '`', inline: true },
        { name: 'HWID Locked', value: '`' + l + '`', inline: true },
        { name: 'All Devices', value: '`' + a + '`', inline: true }
    );

    await interaction.editReply({ embeds: [embed] });
}

async function handleRevoke(interaction) {
    await interaction.deferReply();

    const key = interaction.options.getString('key').trim().toUpperCase();

    const result = await turso.execute({ sql: 'SELECT * FROM keys WHERE key_code = ?', args: [key] });
    if (result.rows.length === 0) {
        await interaction.editReply({ embeds: [createEmbed('Not Found', 'No key found: `' + key + '`', RED)] });
        return;
    }

    const row = result.rows[0];
    if (!row.is_used) {
        await interaction.editReply({ embeds: [createEmbed('Already Free', 'Key `' + key + '` is not used', GRAY)] });
        return;
    }

    await turso.execute({ sql: 'UPDATE keys SET is_used = 0, hwid = "", used_at = "" WHERE key_code = ?', args: [key] });
    await interaction.editReply({ embeds: [createEmbed('Key Revoked', 'Key `' + key + '` has been reset and is now free', GOLD)] });
}

async function handleDelete(interaction) {
    await interaction.deferReply();

    const key = interaction.options.getString('key').trim().toUpperCase();

    const result = await turso.execute({ sql: 'SELECT 1 FROM keys WHERE key_code = ?', args: [key] });
    if (result.rows.length === 0) {
        await interaction.editReply({ embeds: [createEmbed('Not Found', 'No key found: `' + key + '`', RED)] });
        return;
    }

    await turso.execute({ sql: 'DELETE FROM keys WHERE key_code = ?', args: [key] });
    await interaction.editReply({ embeds: [createEmbed('Key Deleted', 'Key `' + key + '` has been permanently deleted', RED)] });
}

async function handleSearch(interaction) {
    await interaction.deferReply();

    const query = interaction.options.getString('query').trim().toLowerCase();

    let sql = 'SELECT * FROM keys WHERE 1=1';
    let args = [];

    if (query === 'used') {
        sql += ' AND is_used = 1';
    } else if (query === 'free') {
        sql += ' AND is_used = 0';
    } else if (query === 'hwid') {
        sql += ' AND locked = 1';
    } else if (query === 'all') {
        sql += ' AND locked = 0';
    } else {
        sql += ' AND group_name = ?';
        args.push(query);
    }

    sql += ' ORDER BY id DESC LIMIT 25';

    const result = await turso.execute({ sql, args });
    const rows = result.rows;

    if (rows.length === 0) {
        await interaction.editReply({ embeds: [createEmbed('No Results', 'No keys found for query: `' + query + '`', GRAY)] });
        return;
    }

    const embed = createEmbed('Search Results', 'Found **' + rows.length + '** keys matching `' + query + '`', GOLD);

    const list = rows.map(r => {
        const s = r.is_used ? 'Used' : 'Free';
        return '`' + r.key_code + '` — ' + s + (r.locked ? ' (HWID)' : '');
    }).join('\n');

    embed.addFields({ name: 'Keys', value: list.length > 1024 ? list.substring(0, 1020) + '...' : list });
    await interaction.editReply({ embeds: [embed] });
}

function parseExpireString(str) {
    const match = str.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 0;
    const val = parseInt(match[1]);
    const unit = match[2];
    switch (unit) {
        case 's': return val * 1000;
        case 'm': return val * 60 * 1000;
        case 'h': return val * 3600 * 1000;
        case 'd': return val * 86400 * 1000;
        default: return 0;
    }
}

module.exports = { startBot, setTurso };
