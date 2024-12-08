package main

// this example is to test the concurrency of the dialer along
// with ensuring that maximum connection time doesn't exceed 3 seconds

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func main() {
	err := BenchmarkDial("scanme.sh", 1000)
	if err != nil {
		panic(err)
	}
}

type connResult struct {
	target  string
	elapsed time.Duration
	err     error
}

func BenchmarkDial(target string, iterations int) error {
	options := fastdialer.DefaultOptions
	fd, err := fastdialer.NewDialer(options)
	if err != nil {
		return errors.Join(err, errors.New("failed to create dialer"))
	}

	ctx := context.Background()

	tasks := make(chan string, iterations)
	results := make(chan connResult, iterations)

	var wg sync.WaitGroup
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go worker(ctx, fd, tasks, results, &wg)
	}

	go func() {
		for i := 0; i < iterations; i++ {
			tasks <- target
		}
		close(tasks)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.err != nil {
			return result.err
		}
		if result.elapsed.Seconds() > 3 {
			return errors.New("connection took too long")
		}
	}

	return nil
}

func worker(ctx context.Context, fd *fastdialer.Dialer, tasks <-chan string, results chan<- connResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range tasks {
		start := time.Now()
		conn, err := fd.Dial(ctx, "tcp", task+":443")
		elapsed := time.Since(start)

		if err == nil && conn != nil {
			conn.Close()
		}

		results <- connResult{
			target:  task,
			elapsed: elapsed,
			err:     err,
		}
	}
}
