// DnsController.cs
using System.ComponentModel.DataAnnotations;
using Backend.Services;
using Microsoft.AspNetCore.Mvc;

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