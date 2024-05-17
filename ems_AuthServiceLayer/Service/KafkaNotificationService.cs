using Bot.CoreBottomHalf.CommonModal.Enums;
using Confluent.Kafka;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModalLayer;
using Newtonsoft.Json;

namespace ems_AuthServiceLayer.Service
{
    public class KafkaNotificationService
    {
        private readonly KafkaServiceConfig _kafkaServiceConfig;
        private readonly ProducerConfig _producerConfig;
        private readonly ILogger<KafkaNotificationService> _logger;
        public readonly DefinedEnvironments _environment;

        public KafkaNotificationService(IOptions<KafkaServiceConfig> options,
            ProducerConfig producerConfig,
            ILogger<KafkaNotificationService> logger,
            DefinedEnvironments environment)
        {
            _kafkaServiceConfig = options.Value;
            _producerConfig = producerConfig;
            _logger = logger;
            _environment = environment;
        }

        public async Task SendEmailNotification(dynamic attendanceRequestModal)
        {
            if (_environment == DefinedEnvironments.Production)
            {
                var result = JsonConvert.SerializeObject(attendanceRequestModal);

                _logger.LogInformation($"[Kafka] Starting kafka service to send message. Topic used: {_kafkaServiceConfig.Topic}, Service: {_kafkaServiceConfig.ServiceName}");
                using (var producer = new ProducerBuilder<Null, string>(_producerConfig).Build())
                {
                    _logger.LogInformation($"[Kafka] Sending message: {result}");
                    await producer.ProduceAsync(_kafkaServiceConfig.Topic, new Message<Null, string>
                    {
                        Value = result
                    });

                    producer.Flush(TimeSpan.FromSeconds(10));
                    _logger.LogInformation($"[Kafka] Message send successfully");
                }
            }

            await Task.CompletedTask;
        }
    }
}
