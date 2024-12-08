using Bot.CoreBottomHalf.CommonModal;
using Bot.CoreBottomHalf.CommonModal.Enums;
using BottomhalfCore.DatabaseLayer.Common.Code;
using BottomhalfCore.DatabaseLayer.MySql.Code;
using BottomhalfCore.Services.Code;
using BottomhalfCore.Services.Interface;
using Bt.Lib.Common.Service.Configserver;
using Confluent.Kafka;
using ems_AuthService.Middlewares;
using ems_AuthServiceLayer.Contracts;
using ems_AuthServiceLayer.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ModalLayer;
using Newtonsoft.Json.Serialization;
using System.Text;

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

var kafkaServerDetail = new ProducerConfig();
builder.Configuration.Bind("KafkaServerDetail", kafkaServerDetail);
builder.Services.Configure<KafkaServiceConfig>(x => builder.Configuration.GetSection(nameof(KafkaServiceConfig)).Bind(x));
builder.Services.Configure<JwtSetting>(o => builder.Configuration.GetSection(nameof(JwtSetting)).Bind(o));

builder.Services.AddSingleton<ProducerConfig>(kafkaServerDetail);
builder.Services.AddSingleton<KafkaNotificationService>(x =>
{
    return new KafkaNotificationService(
        x.GetRequiredService<IOptions<KafkaServiceConfig>>(),
        x.GetRequiredService<ProducerConfig>(),
        x.GetRequiredService<ILogger<KafkaNotificationService>>(),
        builder.Environment.EnvironmentName == nameof(DefinedEnvironments.Development) ?
                        DefinedEnvironments.Development :
                        DefinedEnvironments.Production
    );
});

builder.Services.AddScoped<CurrentSession>(x =>
{
    return new CurrentSession
    {
        Environment = builder.Environment.EnvironmentName == nameof(DefinedEnvironments.Development) ?
                        DefinedEnvironments.Development :
                        DefinedEnvironments.Production
    };
});

builder.Services.AddControllers().AddNewtonsoftJson(options =>
{
    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
    options.SerializerSettings.ContractResolver = new DefaultContractResolver();
});

builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
   .AddJwtBearer(x =>
   {
       x.SaveToken = true;
       x.RequireHttpsMetadata = false;
       x.TokenValidationParameters = new TokenValidationParameters
       {
           ValidateIssuer = false,
           ValidateAudience = false,
           ValidateLifetime = true,
           ValidateIssuerSigningKey = true,
           IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSetting:Key"])),
           ClockSkew = TimeSpan.Zero
       };
   });

builder.Services.AddCors(options =>
{
    options.AddPolicy("bottomhalf-cors", policy =>
    {
        policy.AllowAnyOrigin()
        .AllowAnyHeader()
        .AllowAnyMethod()
        .WithExposedHeaders("Authorization");
    });
});

builder.Services.AddSingleton<IFetchGithubConfigurationService>(x =>
    FetchGithubConfigurationService.getInstance(Bt.Lib.Common.Service.Model.GitRepositories.EMS_CONFIG_SERVICE).GetAwaiter().GetResult()
);

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

app.UseCors("bottomhalf-cors");
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