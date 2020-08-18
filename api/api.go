package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

//FetchNoteByID uses Get API
//https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html
func FetchNoteByID(es *elasticsearch.Client, index string, noteID string) (map[string]interface{}, error) {
	req := esapi.GetRequest{
		Index:      index,
		DocumentID: noteID,
	}
	res, err := req.Do(context.Background(), es)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("Response status: %s", res.Status())
	}
	var resBody map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return nil, fmt.Errorf("Error parsing the response body: %s", err)
	}
	isFound := resBody["found"].(bool)
	if !isFound {
		return nil, fmt.Errorf("Not Found")
	}
	return resBody["_source"].(map[string]interface{}), nil
}

//PostNote uses Index API
//https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
func PostNote(es *elasticsearch.Client, index string, userID string, content string) (string, error) {
	now := time.Now()
	reqBody, err := json.Marshal(map[string]interface{}{
		"userID":    userID,
		"content":   content,
		"createdAt": now,
		"updatedAt": now,
	})
	if err != nil {
		return "", err
	}
	req := esapi.IndexRequest{
		Index:   index,
		Body:    bytes.NewReader(reqBody),
		Refresh: "true",
	}
	res, err := req.Do(context.Background(), es)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.IsError() {
		return "", fmt.Errorf("Response status = %s", res.Status())
	}
	var resBody map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return "", err
	}
	return resBody["_id"].(string), nil
}

//UpdateNote uses Index API
//https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
func UpdateNote(es *elasticsearch.Client, index string, userID string, noteID string, content string) error {
	note, err := FetchNoteByID(es, index, noteID)
	if err != nil {
		return err
	}
	author := note["userID"].(string)
	if userID != author {
		return fmt.Errorf("Forbidden")
	}
	note["content"] = content
	note["updatedAt"] = time.Now()
	reqBody, err := json.Marshal(note)
	if err != nil {
		return err
	}
	req := esapi.IndexRequest{
		Index:      index,
		DocumentID: noteID,
		Body:       bytes.NewReader(reqBody),
		Refresh:    "true",
	}
	res, err := req.Do(context.Background(), es)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("Response status = %s", res.Status())
	}
	return nil
}

//DeleteNote uses Delete API
//https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete.html
func DeleteNote(es *elasticsearch.Client, index string, userID string, noteID string) error {
	note, err := FetchNoteByID(es, index, noteID)
	if err != nil {
		return err
	}
	author := note["userID"].(string)
	if userID != author {
		return fmt.Errorf("Forbidden")
	}
	req := esapi.DeleteRequest{
		Index:      index,
		DocumentID: noteID,
	}
	res, err := req.Do(context.Background(), es)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("Response status = %s", res.Status())
	}
	return nil
}

//SearchNotes uses Search API
//https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html
func SearchNotes(es *elasticsearch.Client, index string, userID string, searchText string, from int, size int) (map[string]interface{}, error) {
	reqBody, err := json.Marshal(map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": map[string]interface{}{
					"intervals": map[string]interface{}{
						"content": map[string]interface{}{
							"match": map[string]interface{}{
								"query":   searchText,
								"ordered": true,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	req := esapi.SearchRequest{
		Index: []string{index},
		Body:  bytes.NewReader(reqBody),
		From:  &from,
		Size:  &size,
	}
	res, err := req.Do(context.Background(), es)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("Response status = %s", res.Status())
	}
	var resBody map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return nil, err
	}
	total := resBody["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)
	hits := resBody["hits"].(map[string]interface{})["hits"].([]interface{})
	notes := make([]map[string]interface{}, len(hits))
	for idx, hit := range hits {
		noteID := hit.(map[string]interface{})["_id"].(string)
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		notes[idx] = map[string]interface{}{
			"noteID":    noteID,
			"userID":    source["userID"],
			"content":   source["content"],
			"createdAt": source["createdAt"],
			"updatedAt": source["updatedAt"],
		}
	}
	searchResult := map[string]interface{}{
		"total": total,
		"hits":  notes,
	}
	return searchResult, nil
}
