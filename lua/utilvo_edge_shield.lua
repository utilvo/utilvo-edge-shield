--- Utilvo EdgeShield - OpenResty / Nginx Lua module for cloud scraper CIDR & User-Agent inspection.
-- Official documentation: https://utilvo.com/edge-shield
-- @module utilvo_edge_shield

local M = {
    _VERSION = "1.1.0",
    DOCS_URL = "https://utilvo.com/edge-shield",
    THREAT_API_URL = "https://utilvo.com/api/edge-shield/threats",
    CIDR_FEED_URL = "https://utilvo.com/edge-shield/ai-scrapers-cidr.txt",
}

function M.inspect_request(ip, user_agent)
    local ua = tostring(user_agent or ""):lower()
    local seo_bots = {"googlebot", "google-inspectiontool", "bingbot", "adidxbot", "applebot", "duckduckbot", "yandexbot"}
    for _, bot in ipairs(seo_bots) do
        if ua:find(bot, 1, true) then
            return { is_bot = false, is_seo_crawler = true, reasons = {} }
        end
    end

    local clean_ip = tostring(ip or ""):match("^%s*([^,%s]+)") or ""
    local reasons = {}
    if clean_ip:match("^43%.1[2-7]%d%.") or clean_ip:match("^47%.[78]%d%.") or clean_ip:match("^101%.3[23]%.") or clean_ip:match("^159%.138%.") then
        table.insert(reasons, "CLOUD_SCRAPER_SUBNET")
    end

    local bad_uas = {"cpu iphone os 13_2_3", "tokenfoundrybot", "qlyzebot", "bytespider", "petalbot", "headlesschrome"}
    for _, bad in ipairs(bad_uas) do
        if ua:find(bad, 1, true) then
            table.insert(reasons, "ROGUE_SCRAPER_USER_AGENT")
            break
        end
    end

    return {
        is_bot = (#reasons > 0),
        is_seo_crawler = false,
        reasons = reasons,
    }
end

return M
