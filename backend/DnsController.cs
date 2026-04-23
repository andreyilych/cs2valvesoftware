using Backend.Services;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Backend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DnsController : ControllerBase
{
    private readonly DnsCheckerService _service;
    private readonly ILogger<DnsController> _logger;

    public DnsController(DnsCheckerService service, ILogger<DnsController> logger)
    {
        _service = service;
        _logger = logger;
    }

    /// <summary>POST /api/dns/check</summary>
    [HttpPost("check")]
    public ActionResult<DnsCheckResult> Check([FromBody] DnsCheckRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            var result = _service.CheckDomain(request.Domain);
            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>GET /api/dns/check?domain=google.com</summary>
    [HttpGet("check")]
    public ActionResult<DnsCheckResult> CheckGet([FromQuery, Required] string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return BadRequest(new { error = "Параметр domain обязателен." });

        try
        {
            var result = _service.CheckDomain(domain);
            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Проверка, что сервер жив.</summary>
    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok(new { status = "ok", timestamp = DateTime.UtcNow });
    }
}

public class DnsCheckRequest
{
    [Required(ErrorMessage = "Домен обязателен.")]
    [MinLength(3, ErrorMessage = "Слишком короткий домен.")]
    public string Domain { get; set; } = "";
}