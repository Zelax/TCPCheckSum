#include <stdint.h>

/**
 * \brief Прототип функции вычисляющей контрольную сумму.
 * \param data буфер, контрольную сумму которого нужно вычислить
 * \param len длина буфера в байтах
 * \param init начальное значение контрольной суммы. Может быть использовано
 *             для продолжения вычислений, если части одного буфера лежат в разных
 *             местах памяти. Например, TCP-псеводо заголовок и сам TCP-сегмент.
 * \return вычисленная контрольная сумма
 */
typedef uint16_t (*checksum_t)(uint8_t *data, uint16_t len, uint16_t init);

enum checksum_algorithm {
  CSA_C,
#ifdef ALG_AMD64
  CSA_AMD64,
#endif
  CSA_COUNT
};

// Таблица алгоритмов вычисления контрольной суммы. Для выбора алгоритма использовать
// checksum_algorithm.
extern checksum_t checksum_funcs[CSA_COUNT];
