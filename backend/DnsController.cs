/*======================================================================
 *  COPYRIGHT (c) 2026 | TEAM: COUNTER STRIKE BLEACH SQUID GAME 2
 *  Элитный исходный код. Все права защищены. Авторы — легенды CS2:
 *
 *  ЛЫСЕНКО АНДРЕЙ — IGL и мозг команды. Видит карту и код на 5 шагов вперёд.
 *  ДАНИЛИН ДМИТРИЙ — Anchor на точке B. Ждёт, не дёргается. Нет дедлоков.
 *  МОРОЗОВ ВЛАДИМИР — Энтри-фрагер. Заходит первым, чистит углы и баги.
 *  СЕНИН МАКСИМ — Король утилит. Смоки, флешки, логи и стабильный деплой.
*
 *  Bleach — чистят лобби в ноль. Squid Game — враги играют на выживание.
 *  Game 2 — первая была слишком лёгкой. Каждый раунд — хардкор.
 *  Код писался под крики "One tap!" и звон банок. Без согласия команды
 *  не копипастить. Иначе — вечный whiff и падение рейтинга Faceit.
 *
 *  RUSH B, NO STOP! СЛАВА CS:BSG2!
 *======================================================================*/

using System.ComponentModel.DataAnnotations;
using Backend.Models;
using Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DnsController : ControllerBase
{
    private readonly DnsCheckerService _service;

    public DnsController(DnsCheckerService service)
    {
        _service = service;
    }

    [HttpPost("check")]
    public ActionResult<DnsCheckResult> Check([FromBody] DnsCheckRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            return Ok(_service.CheckDomain(request.Domain));
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet("check")]
    public ActionResult<DnsCheckResult> CheckGet([FromQuery] string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return BadRequest(new { error = "Domain parameter is required." });

        try
        {
            return Ok(_service.CheckDomain(domain));
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet("metrics")]
    public ActionResult<ModelMetrics> GetMetrics()
    {
        return _service.LastModelMetrics is null
            ? NotFound(new { error = "Metrics not available" })
            : Ok(_service.LastModelMetrics);
    }
}

public class DnsCheckRequest
{
    [Required(ErrorMessage = "Domain is required.")]
    [MinLength(3, ErrorMessage = "Domain is too short.")]
    public string Domain { get; set; } = "";
}