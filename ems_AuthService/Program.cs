using Bot.CoreBottomHalf.CommonModal;
using BottomhalfCore.DatabaseLayer.Common.Code;
using BottomhalfCore.DatabaseLayer.MySql.Code;
using BottomhalfCore.Services.Code;
using BottomhalfCore.Services.Interface;
using Bt.Lib.PipelineConfig.MicroserviceHttpRequest;
using Bt.Lib.PipelineConfig.Middlewares;
using Bt.Lib.PipelineConfig.Services;
using ems_AuthServiceLayer.Contracts;
using ems_AuthServiceLayer.Models;
using ems_AuthServiceLayer.Service;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables();

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddScoped<ILoginService, LoginService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddSingleton<IDb, Db>();
builder.Services.AddSingleton<ITimezoneConverter, TimezoneConverter>(x =>
{
    return TimezoneConverter.Instance;
});
builder.Services.AddSingleton<ApplicationConfiguration>();
builder.Services.Configure<MicroserviceRegistry>(x => builder.Configuration.GetSection(nameof(MicroserviceRegistry)).Bind(x));
builder.Services.AddSingleton(resolver =>
    resolver.GetRequiredService<IOptions<MicroserviceRegistry>>().Value
);
builder.Services.AddSingleton<GitHubConnector>();
builder.Services.AddScoped<RequestMicroservice>();
builder.Services.AddHttpClient();

var commonRegistry = new PipelineRegistry(builder.Services, builder.Environment, builder.Configuration);
commonRegistry.AddCORS("EmstumCORS")
    .AddPublicKeyConfiguration()
    .AddCurrentSessionClass()
    .AddKafkaProducerService()
    .AddJWTSupport()
    .RegisterJsonHandler();

// builder.Services.AddHostedService<KafkaService>();
var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<ExceptionHandlerMiddleware>();
app.UseRouting();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateTime.Now.AddDays(index),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

app.UseCors("EmstumCORS");
app.UseMiddleware<RequestMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints => endpoints.MapControllers());
app.MapControllers();
app.Run();

internal record WeatherForecast(DateTime Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}